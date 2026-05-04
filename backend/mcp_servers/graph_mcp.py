"""MCP server exposing graph write/read tools to the agent.

Investigation id is read from env BOUNCE_INV_ID (set by backend when spawning claude).
"""
import os
from mcp.server.fastmcp import FastMCP
from .. import graph_store as gs
from .. import key_pool
from ..defuse_lists import defuse_check
from ..pivot_mapping import (
    pivots_for, MAX_HIGH_PRIO_PER_NODE, MAX_LOW_PRIO_PER_NODE,
)

INV_ID = os.environ.get("BOUNCE_INV_ID", "default")
mcp = FastMCP("bounce-graph")


def _auto_enqueue_pivots(type_: str, value: str) -> dict:
    """Idempotent: enqueue all applicable pivots for a node, respecting
    defuse status, available API keys, and per-node fan-out caps. Returns
    {enqueued, skipped} counts (0/0 if no pivots apply for this type)."""
    defused = False
    if type_ in ("ip", "domain", "ns"):
        try:
            d = defuse_check(type_, value)
            defused = bool(d.get("should_stop_pivot"))
        except Exception:
            pass

    rules = pivots_for(type_, value, has_key=key_pool.has_any_key, defused=defused)
    if not rules:
        return {"enqueued": 0, "skipped": 0}

    pending_high = [r for r in rules if r[2] is None and r[1] <= 3]
    pending_low = [r for r in rules if r[2] is None and r[1] >= 4]
    skipped = [r for r in rules if r[2] is not None]

    pending_high = pending_high[:MAX_HIGH_PRIO_PER_NODE]
    pending_low = pending_low[:MAX_LOW_PRIO_PER_NODE]

    enq = 0
    for op, prio, _ in (pending_high + pending_low):
        if gs.enqueue_pivot(INV_ID, type_, value, op, priority=prio,
                             status="pending")["was_new"]:
            enq += 1
    for op, prio, reason in skipped:
        gs.enqueue_pivot(INV_ID, type_, value, op, priority=prio,
                         status="skipped", skip_reason=reason)
    return {"enqueued": enq, "skipped": len(skipped)}


@mcp.tool()
def add_node(type: str, value: str, metadata: dict | None = None,
             confidence: float = 0.8, source: str = "agent",
             tags: list[str] | None = None) -> dict:
    """Add or merge a node in the investigation graph.

    type: one of domain, ip, hash, url, cert, asn, email, registrar, ns,
          favicon_hash, jarm, ja3, cert_serial, tracking_id, form_action,
          wallet_address, js_hash, title_hash, report
    value: the node identifier (e.g. the domain string)
    metadata: free-form dict (whois, geo, ports, etc.)
    confidence: 0..1
    source: name of the source ("crtsh", "vt", "agent", ...)
    tags: list of semantic tags (e.g. ["cdn", "parking"])

    Side effect: pivots applicable to this node type are auto-enqueued in
    the pivot_tasks table. Call ``next_pivot()`` to drain the queue.
    """
    result = gs.add_node(INV_ID, type, value, metadata=metadata,
                         confidence=confidence, source=source, tags=tags)
    enq = _auto_enqueue_pivots(type, value)
    if enq["enqueued"] or enq["skipped"]:
        result["pivots_queued"] = enq["enqueued"]
        result["pivots_skipped"] = enq["skipped"]
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
def get_graph(compact: bool = False) -> dict:
    """Return the current investigation graph (nodes + edges).

    For large graphs (50+ nodes), use compact=True to get a summary that fits
    within tool output limits. Compact mode returns:
      - nodes: list of {id, type, value, tags, confidence} (no metadata)
      - edges: list of {src, dst, relation} (no evidence/confidence)
      - stats: {node_count, edge_count, type_counts}
    Report metadata is NOT included in compact mode — call get_report()
    separately to get the report.

    Full mode (compact=False) returns all nodes and edges with full metadata.
    If the graph is very large, full mode may exceed output limits and fail;
    in that case, retry with compact=True and use get_node() for specific nodes.
    """
    graph = gs.get_graph(INV_ID)
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
def defuse(kind: str, value: str) -> dict:
    """Check if an indicator is a CDN/parking/sinkhole/dyndns. ALWAYS call before pivoting on an IP or NS.

    kind: ip | domain | ns
    Returns {tags, reasons, should_stop_pivot}.
    """
    return defuse_check(kind, value)


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
    """
    return gs.acquire_pivot(INV_ID) or {}


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

    n = gs.requeue_missing(INV_ID, mapping)
    return {"enqueued": n}


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
      {source: {keys_total, keys_available, keys_cooldown, used_today_per_key}}.
    Useful to redirect to alternative sources when a primary is rate-limited.
    """
    return key_pool.status_all()


if __name__ == "__main__":
    mcp.run()
