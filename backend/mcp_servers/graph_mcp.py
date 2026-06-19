"""MCP server exposing graph write/read tools to the agent.

Investigation id is read from env BOUNCE_INV_ID (set by backend when spawning claude).
"""
import os
from typing import Optional
from mcp.server.fastmcp import FastMCP
from .. import graph_store as gs
from .. import key_pool
from .. import source_health
from ..defuse_lists import defuse_check
from ..pivot_mapping import (
    pivots_for, MAX_HIGH_PRIO_PER_NODE, MAX_LOW_PRIO_PER_NODE, MAX_PENDING_QUEUE,
    canonical_type, cloud_platform_domain, _CLOUD_PLATFORM_SUPPRESSED_OPS,
    is_role_mailbox, _EMAIL_PIVOT_OPS, is_hex_serial, _SERIAL_OPS,
    known_bad_marker, actor_handle_for_tag, kit_handle_for_tag, key_source_for_op,
)

INV_ID = os.environ.get("BOUNCE_INV_ID", "default")
mcp = FastMCP("bounce-graph")


def _suppressed_ops(type_: str, value: str) -> set:
    """Ops to skip at enqueue time because they are structurally doomed /
    pure noise for this specific node (not a defuse — a target-shape filter)."""
    ctype = canonical_type(type_)
    if type_ == "domain" and cloud_platform_domain(value):
        return set(_CLOUD_PLATFORM_SUPPRESSED_OPS)
    if type_ == "email" and is_role_mailbox(value):
        return set(_EMAIL_PIVOT_OPS)
    if ctype == "cert_serial" and not is_hex_serial(value):
        return set(_SERIAL_OPS)
    return set()


def _auto_enqueue_pivots(type_: str, value: str) -> dict:
    """Idempotent: enqueue all applicable pivots for a node, respecting
    defuse status, available API keys, per-node fan-out caps, target-shape
    noise filters (shared-SaaS domains / role mailboxes / non-hex serials),
    and a global pending-queue ceiling. Returns {enqueued, skipped, deferred}."""
    defused = False
    if type_ in ("ip", "domain", "ns"):
        try:
            d = defuse_check(type_, value)
            defused = bool(d.get("should_stop_pivot"))
        except Exception:
            pass

    try:
        vertical = gs.get_vertical(INV_ID)
    except Exception:
        vertical = "cti"
    rules = pivots_for(type_, value, has_key=key_pool.has_any_key,
                       defused=defused, vertical=vertical)
    if not rules:
        return {"enqueued": 0, "skipped": 0, "deferred": 0}

    suppress = _suppressed_ops(type_, value)

    # Source-health gate: if a pivot needs a source currently marked dead (e.g.
    # OpenCTI token expired this run), skip it at enqueue time so we don't
    # rediscover the auth failure on every node. Self-heals via TTL.
    def _is_op_source_dead(op: str) -> Optional[str]:
        src = key_source_for_op(op)
        if not src:
            return None
        st = source_health.is_dead(src)
        return f"source_dead:{st['status']}" if st else None

    pending_high = []
    pending_low = []
    source_dead = []  # ops we skipped because their source is marked dead
    for op, prio, key_required in rules:
        if key_required is not None:
            continue  # already classified as skipped (no_api_key/defused)
        if op in suppress:
            continue  # already classified as noise_filter
        sd = _is_op_source_dead(op)
        if sd:
            source_dead.append((op, prio, sd))
            continue
        (pending_high if prio <= 3 else pending_low).append((op, prio, None))
    skipped = [r for r in rules if r[2] is not None]
    # Suppressed ops become visible 'skipped' rows (not silently dropped) so the
    # analyst sees why they weren't run.
    noise = [(op, prio, "noise_filter") for op, prio, reason in rules
             if reason is None and op in suppress]

    pending_high = pending_high[:MAX_HIGH_PRIO_PER_NODE]
    pending_low = pending_low[:MAX_LOW_PRIO_PER_NODE]

    # Global queue governor: once the backlog is large, park new auto-enqueues
    # as 'deferred' (skip_reason='queue_ceiling') so drain budget goes to work
    # already queued. requeue_missing() can promote them later if needed.
    try:
        over_ceiling = gs.pending_pivot_count(INV_ID) >= MAX_PENDING_QUEUE
    except Exception:
        over_ceiling = False

    enq = 0
    deferred = 0
    for op, prio, _ in (pending_high + pending_low):
        if over_ceiling:
            gs.enqueue_pivot(INV_ID, type_, value, op, priority=prio,
                             status="deferred", skip_reason="queue_ceiling")
            deferred += 1
            continue
        if gs.enqueue_pivot(INV_ID, type_, value, op, priority=prio,
                             status="pending")["was_new"]:
            enq += 1
    for op, prio, reason in (skipped + noise + source_dead):
        gs.enqueue_pivot(INV_ID, type_, value, op, priority=prio,
                         status="skipped", skip_reason=reason)
    return {"enqueued": enq, "skipped": len(skipped) + len(noise) + len(source_dead),
            "deferred": deferred}


@mcp.tool()
def add_node(type: str, value: str, metadata: dict | None = None,
             confidence: float = 0.8, source: str = "agent",
             tags: list[str] | None = None) -> dict:
    """Add or merge a node in the investigation graph.

    type: one of domain, ip, hash, url, cert, asn, email, registrar, ns,
          favicon_hash, jarm, ja3, ja3s, cert_serial, tracking_id, form_action,
          wallet_address, js_hash, title_hash, person, threat_actor,
          phishing_kit, report

          threat_actor: a named adversary / intrusion set / campaign (e.g.
            "UNC1549", "MuddyWater"). You normally don't create this by hand —
            tag a node with a known actor handle and add_node auto-promotes it
            to a threat_actor node + attributed_to edge. Create directly only
            when you have explicit, corroborated attribution.

          phishing_kit: a named phishing / PhaaS kit or framework (e.g.
            "Tycoon 2FA", "EvilProxy"). Like threat_actor, you normally don't
            create this by hand — tag a node with a known kit handle and add_node
            auto-promotes it to a phishing_kit node + uses_kit edge.

          jarm / ja3 / ja3s are distinct TLS fingerprints and pivot
          differently — do NOT file a JA3/JA3S under `jarm`. JARM is a
          62-hex active server fingerprint; JA3 (client) and JA3S (server)
          are 32-hex MD5 digests. The store auto-corrects an obvious
          mislabel from metadata.type / value shape, but pass the right
          type when you know it.

          person: create ONLY when multiple strong, convergent indicators
            point at the same individual / operator (e.g. the same operator
            email surfaces in both RDAP and SOA, OR an identity is named
            directly in DNS TXT / WHOIS organisation / certificate subject).
            Never spawn a person node from a single weak signal. Value should
            be the canonical display name or handle (e.g. "John Doe" or
            "@operator-handle"); put the corroborating emails / handles /
            sources in metadata={emails:[], handles:[], evidence:[]}.
    value: the node identifier (e.g. the domain string)
    metadata: free-form dict (whois, geo, ports, etc.)
    confidence: 0..1
    source: name of the source ("crtsh", "vt", "agent", ...)
    tags: list of semantic tags (e.g. ["cdn", "parking"])

    Side effect: pivots applicable to this node type are auto-enqueued in
    the pivot_tasks table. Call ``next_pivot()`` to drain the queue.
    """
    # Auto-tag documented known-bad tool defaults (e.g. Cobalt Strike default
    # cert serial) so the agent doesn't have to recall the fingerprint.
    kb = known_bad_marker(type, value)
    if kb:
        tag, note = kb
        tags = list(set((tags or []) + [tag]))
        metadata = dict(metadata or {})
        metadata.setdefault("known_bad_marker", note)

    result = gs.add_node(INV_ID, type, value, metadata=metadata,
                         confidence=confidence, source=source, tags=tags)
    enq = _auto_enqueue_pivots(type, value)
    if enq["enqueued"] or enq["skipped"] or enq.get("deferred"):
        result["pivots_queued"] = enq["enqueued"]
        result["pivots_skipped"] = enq["skipped"]
        if enq.get("deferred"):
            result["pivots_deferred"] = enq["deferred"]

    # Promote a known threat-actor handle from this node's tags to a first-class
    # `threat_actor` node + `attributed_to` edge. Normalisation of the agent's
    # own finding (the tag is its evidence) — provenance preserved so it isn't a
    # fabricated attribution.
    promoted = []
    for t in (tags or []):
        actor = actor_handle_for_tag(t)
        if not actor:
            continue
        gs.add_node(INV_ID, "threat_actor", actor,
                    metadata={"promoted_from_tag": t,
                              "evidence": f"tag '{t}' on {type}:{value}",
                              "source": "tag_promotion"},
                    confidence=min(confidence, 0.7), source="tag_promotion",
                    tags=["attribution"])
        gs.add_edge(INV_ID, type, value, "threat_actor", actor,
                    "attributed_to", evidence=f"tag '{t}'", source="tag_promotion",
                    confidence=min(confidence, 0.7))
        promoted.append(actor)
    if promoted:
        result["threat_actors_promoted"] = promoted

    # Same normalisation for phishing-kit / PhaaS handles: promote a known kit
    # tag to a first-class `phishing_kit` node + `uses_kit` edge so the tooling
    # attribution is queryable (e.g. Tycoon 2FA) rather than buried in a tag.
    kits_promoted = []
    for t in (tags or []):
        kit = kit_handle_for_tag(t)
        if not kit:
            continue
        gs.add_node(INV_ID, "phishing_kit", kit,
                    metadata={"promoted_from_tag": t,
                              "evidence": f"tag '{t}' on {type}:{value}",
                              "source": "tag_promotion"},
                    confidence=min(confidence, 0.7), source="tag_promotion",
                    tags=["attribution"])
        gs.add_edge(INV_ID, type, value, "phishing_kit", kit,
                    "uses_kit", evidence=f"tag '{t}'", source="tag_promotion",
                    confidence=min(confidence, 0.7))
        kits_promoted.append(kit)
    if kits_promoted:
        result["phishing_kits_promoted"] = kits_promoted
    return result


@mcp.tool()
def add_edge(src_type: str, src_value: str, dst_type: str, dst_value: str,
             relation: str, evidence: str = "", source: str = "agent",
             confidence: float = 0.8) -> dict:
    """Add an edge between two nodes.

    relation examples: resolves_to, has_subdomain, shares_cert, same_registrant,
    same_ns, same_favicon, same_jarm, hosted_on_asn, communicates_with,
    historical_resolution
    """
    return gs.add_edge(INV_ID, src_type, src_value, dst_type, dst_value,
                       relation, evidence=evidence, source=source, confidence=confidence)


@mcp.tool()
def tag_node(type: str, value: str, tag: str | None = None,
             tags: list[str] | None = None) -> str:
    """Tag a node (cdn, parking, sinkhole, dyndns, shared_hosting, suspicious, benign, etc.).

    Pass either `tag` (single) or `tags` (list). Both are accepted for convenience.
    """
    items: list[str] = []
    if tag:
        items.append(tag)
    if tags:
        items.extend(tags)
    for t in items:
        gs.tag_node(INV_ID, type, value, t)
    return "ok"


@mcp.tool()
def get_graph(compact: bool = False, stats_only: bool = False) -> dict:
    """Return the current investigation graph (nodes + edges).

    For large graphs (50+ nodes), use compact=True to get a summary that fits
    within tool output limits. Compact mode returns:
      - nodes: list of {id, type, value, tags, confidence} (no metadata)
      - edges: list of {src, dst, relation} (no evidence/confidence)
      - stats: {node_count, edge_count, type_counts}
    Report metadata is NOT included in compact mode — call get_report()
    separately to get the report.

    stats_only=True returns ONLY {stats: {node_count, edge_count, type_counts,
    tag_counts}} with no node/edge lists at all — use this in the
    retrospective / report phases when you only need the graph SHAPE, not its
    content (compact mode on a 150-node graph still blew the token limit at
    ~69k chars). Cheapest possible call.

    Full mode (compact=False) returns all nodes and edges with full metadata.
    If the graph is very large, full mode may exceed output limits and fail;
    in that case, retry with compact=True and use get_node() for specific nodes.
    """
    graph = gs.get_graph(INV_ID)
    if stats_only:
        from collections import Counter
        nodes = [n for n in graph.get("nodes", []) if n.get("type") != "report"]
        tag_counts: Counter = Counter()
        for n in nodes:
            for t in (n.get("tags") or []):
                tag_counts[t] += 1
        return {"stats": {
            "node_count": len(nodes),
            "edge_count": len(graph.get("edges", [])),
            "type_counts": dict(Counter(n["type"] for n in nodes)),
            "tag_counts": dict(tag_counts),
        }}
    if not compact:
        return graph
    # Compact mode: strip metadata from non-report nodes, simplify edges
    nodes_compact = []
    for n in graph.get("nodes", []):
        if n.get("type") == "report":
            continue  # report data accessed via get_report()
        nodes_compact.append({
            "id": n.get("id"),
            "type": n.get("type"),
            "value": n.get("value"),
            "tags": n.get("tags", []),
            "confidence": n.get("confidence"),
        })
    edges_compact = [
        {"src": e.get("src"), "dst": e.get("dst"), "relation": e.get("relation")}
        for e in graph.get("edges", [])
    ]
    from collections import Counter
    type_counts = dict(Counter(n["type"] for n in nodes_compact))
    return {
        "nodes": nodes_compact,
        "edges": edges_compact,
        "stats": {
            "node_count": len(nodes_compact),
            "edge_count": len(edges_compact),
            "type_counts": type_counts,
        },
    }


@mcp.tool()
def get_node(type: str, value: str) -> dict | None:
    """Return a single node with full metadata. Use this to inspect specific
    nodes when the full graph is too large to retrieve at once."""
    graph = gs.get_graph(INV_ID)
    for n in graph.get("nodes", []):
        if n.get("type") == type and n.get("value") == value:
            return n
    return None


@mcp.tool()
def get_report() -> dict:
    """Return just the report node metadata (summary, threat_assessment,
    key_findings, prompt_history, etc.). Faster and smaller than get_graph
    when you only need the report."""
    graph = gs.get_graph(INV_ID)
    for n in graph.get("nodes", []):
        if n.get("type") == "report" and n.get("value") == "investigation_summary":
            return n.get("metadata", {})
    return {}


@mcp.tool()
def defuse(kind: str, value: str,
           registrant: str | None = None,
           registrar: str | None = None) -> dict:
    """Check if an indicator is a CDN / parking / sinkhole / blackhole / dyndns.
    ALWAYS call before pivoting on an IP or NS.

    kind: ip | domain | ns
    registrant / registrar: optional RDAP-side strings (e.g. registrant email,
      org, or `registrar` field). When supplied, they are matched against the
      LE-takedown handler list (FBI/DOJ/Europol/Microsoft DCU/Shadowserver/
      Spamhaus/...). A match marks the indicator `sinkhole_kind="le_seized"`
      so the agent KEEPS pivoting for historical residue rather than early-exiting.

    Returns:
      {
        tags:              list[str]   # cdn | parking | sinkhole | blackhole | dyndns
        reasons:           list[str]   # one human line per signal
        sinkhole_kind:     str | None  # le_seized | monitoring | blackhole | None
        should_stop_pivot: bool        # True for commercial defuse + monitoring sinkholes.
                                       # False for LE seizures (mine historical residue).
      }
    """
    return defuse_check(kind, value, registrant=registrant, registrar=registrar)


# ── Pivot queue / autonomy engine tools ────────────────────────────────

@mcp.tool()
def next_pivot() -> dict:
    """Pop the next pending pivot from the queue (highest priority first,
    then FIFO). Marks it 'running' atomically. Returns:
      {task_id, node_type, node_value, pivot_op, priority}
    or {} if the queue is empty.

    After executing the pivot's tool, call mark_pivot_done(task_id, summary)
    so the queue stays consistent. If the queue is empty, call coverage_matrix
    and requeue_missing to ensure no expected pivots were skipped.

    NOTE: directly-invoked CTI tools are now auto-reconciled into the queue, so
    a pivot you already ran by hand won't be handed back to you here.
    """
    task = gs.acquire_pivot(INV_ID) or {}
    # Surface key-pool / quota state for the pivot's source so the agent can
    # skip a tool it has no working key for instead of discovering the failure
    # after the call.
    if task.get("pivot_op"):
        try:
            src = key_source_for_op(task["pivot_op"])
            if src:
                task["source_state"] = key_pool.status(src)
                # Surface 'source_dead' (auth_required / quota_exhausted /
                # zero_balance) flags too so the agent sees a systemic failure
                # before calling the tool, not after.
                dead = source_health.is_dead(src)
                if dead:
                    task["source_state"]["dead"] = dead
        except Exception:
            pass
    return task


@mcp.tool()
def mark_pivot_done(task_id: str, summary: str = "",
                    status: str = "done") -> dict:
    """Close a pivot task. status: 'done' | 'failed' | 'skipped'.

    `summary` is a short human-readable note (≤ 500 chars) of what the pivot
    found, e.g. "5 subdomains, 1 new IP" or "no records". Stored for
    later inclusion in gaps_report.
    """
    ok = gs.complete_pivot(task_id, status=status, summary=summary)
    return {"ok": ok}


@mcp.tool()
def queue_status() -> dict:
    """Return aggregate counts of pivot tasks for this investigation:
      {pending, running, done, skipped, failed, by_op: {op: {status: n}}}.
    Use this to decide whether to keep draining or transition to
    EXHAUSTION_CHECK / REPORT.
    """
    return gs.pivot_queue_status(INV_ID)


@mcp.tool()
def coverage_matrix(only_with_gaps: bool = False) -> list[dict]:
    """Return per-node pivot coverage:
      [{node_id, node_type, node_value, pivots_done, pivots_pending,
        pivots_skipped, pivots_failed, pivots_running}].

    If `only_with_gaps=True`, returns only nodes that have at least one
    pivot in pending/running/failed status (i.e. nodes still in flight or
    that need attention). Use this in EXHAUSTION_CHECK before allowing
    transition to REPORT.
    """
    rows = gs.coverage_matrix(INV_ID)
    if only_with_gaps:
        rows = [r for r in rows
                if r["pivots_pending"] or r["pivots_running"] or r["pivots_failed"]]
    return rows


@mcp.tool()
def requeue_missing() -> dict:
    """For every node in the graph, ensure all expected pivots have been
    enqueued. Returns {enqueued: int} -- the count of pivots that were
    missing and have just been added to 'pending'. A return of 0 confirms
    full structural coverage (every node has been considered for every
    applicable pivot).

    Call this before transitioning to REPORT.
    """
    def mapping(node_type: str, node_value: str) -> list[tuple[str, int]]:
        defused = False
        if node_type in ("ip", "domain", "ns"):
            try:
                d = defuse_check(node_type, node_value)
                defused = bool(d.get("should_stop_pivot"))
            except Exception:
                pass
        rules = pivots_for(node_type, node_value, has_key=key_pool.has_any_key,
                            defused=defused)
        return [(op, prio) for op, prio, reason in rules if reason is None]

    promoted = gs.promote_deferred_pivots(INV_ID)
    n = gs.requeue_missing(INV_ID, mapping)
    return {"enqueued": n, "promoted_from_deferred": promoted}


@mcp.tool()
def gaps_report() -> dict:
    """Grouped view of pivots that were skipped or failed, keyed by reason
    (no_api_key, defused, rate_limit, fanout_per_node, etc.). Use this
    in SELF_CRITIQUE before writing the final report so the analyst sees
    exactly what was *not* tried and why.
    """
    return gs.gaps_report(INV_ID)


@mcp.tool()
def quota_status() -> dict:
    """Snapshot of API key pool state across all configured sources:
      {sources: {source: {keys_total, keys_available, keys_cooldown,
                          used_today_per_key}},
       dead_sources: {source: {status, reason, since}}}.

    `dead_sources` lists sources flagged as systemically non-functional for
    this run (e.g. OpenCTI token expired). Pivots needing a dead source are
    skipped at enqueue time and surface in gaps_report with
    skip_reason='source_dead:<status>'. The flag self-heals after a short TTL
    so a fixed key recovers automatically.
    """
    return {
        "sources": key_pool.status_all(),
        "dead_sources": source_health.snapshot(),
    }


@mcp.tool()
def mitre_attack_candidates() -> dict:
    """Heuristic MITRE ATT&CK technique candidates for THIS investigation.

    Runs a deterministic mapper over the current graph (tags + PE imports
    from sample_analysis) and returns a starting list of (technique_id,
    technique_name, tactics, rationales, evidence_node_ids, confidence).
    Call this AFTER the main investigation is done and BEFORE writing
    the final report. The agent MUST:

      1. Read each candidate, validate it against the evidence
         (look up the cited node, confirm the rationale holds).
      2. Add ONLY validated entries to ``report.metadata.mitre_attack_mapping``
         (drop spurious ones, refine rationales with quotes from tool output).
      3. NEVER invent ATT&CK technique IDs not returned here — if a
         technique is clearly relevant but not in the candidate list,
         note it in `mitre_attack_mapping.analyst_added` with full
         justification rather than fabricating a TID match.

    Empty result is fine — pure-infrastructure investigations often
    only yield T1071.* generically. Note that explicitly in the report.
    """
    from .. import mitre_mapping
    graph = gs.get_graph(INV_ID)
    return {"candidates": mitre_mapping.map_graph(graph)}


@mcp.tool()
def cross_investigation_lookup(type: str, value: str, limit: int = 25) -> dict:
    """Find every prior investigation (same owner) where this (type, value)
    node was already observed. Use this on KEY infrastructure pivots —
    suspicious JARMs, registrar emails, C2 IPs, malware hashes — to detect
    repeat infrastructure across campaigns. Each returned hit comes with
    the prior investigation's seed and metadata-key list so you can decide
    whether to record a `seen_in_prior_investigation` evidence note on the
    current node. Scope: ONLY investigations owned by the same user.

    Returns ``{"hits": [...], "count": N}`` (count clamped to ``limit``).
    Empty hits means this is the first time this IOC appears in this
    user's investigation history — useful negative signal.
    """
    owner = gs.get_investigation_owner(INV_ID)
    hits = gs.find_node_across_investigations(
        type, value, user_id=owner, exclude_inv=INV_ID, limit=limit
    )
    return {"hits": hits, "count": len(hits)}


if __name__ == "__main__":
    mcp.run()
