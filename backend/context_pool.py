"""Context pool — the *second epistemic tier* of the investigation graph.

Bounce's primary tiers (the ~90 `mcp__cti__*` / `mcp__dd__*` source tools) return
**observations**: something a third party published and we can re-query. This
module governs a different, weaker class of input:

  * the agent's own **parametric memory** (what the model "knows" from training),
  * **open-web** text pulled by the wrapped `web_search` / `web_fetch` tools.

Both are useful — they are often the only way to name a campaign, route a company
to the right registry, or connect a handle to a public project. Both are also
**unverifiable at the point of production**: memory hallucinates, and web text is
attacker-controllable (a page can contain prompt-injection payloads).

The design rule this module encodes is therefore:

    Claude is not another source. Claude is the HYPOTHESIS GENERATOR,
    and the existing source pool is its JURY.

Concretely, everything entering through the context pool becomes a ``lead``
node — never a typed IOC — with:

  * ``source``      = ``parametric_memory`` or ``web:<host>``
  * ``confidence``  ≤ :data:`LEAD_CONFIDENCE_CAP` (clamped **server-side**, so the
                      agent cannot promote its own guess by passing 0.9)
  * a lifecycle tag ``unverified`` → ``corroborated`` | ``refuted``

A ``lead`` is promoted to a real typed node only when a *primary* source tool
confirms it (:func:`is_primary_evidence_tool`). Until then it is excluded from
every actionable export (blocklist / detection rules / takedown / STIX) by
:func:`is_actionable`.

That single mechanism covers **both** failure modes at once:
hallucination *and* prompt injection — injected text can only ever mint a
low-confidence, non-exportable lead that a primary source must ratify.

The module is deliberately pure (no I/O, no MCP, no DB) so the guarantees are
unit-testable in isolation: see ``backend/tests/test_context_pool.py``.
"""
from __future__ import annotations

import ipaddress
import os
import re
from typing import Iterable, Optional
from urllib.parse import urlparse

# ── The hard ceiling ───────────────────────────────────────────────────────
# Applied in graph_mcp.add_node, NOT in the prompt. A prompt rule is a
# suggestion; this is an invariant. 0.35 sits below every "normal" confidence
# the agent uses (0.7-0.9) and below the 0.5 mark most UI/scoring treats as
# "probable", so a lead can never read as an established fact.
LEAD_CONFIDENCE_CAP = 0.35

# The node type every context-pool input collapses to.
LEAD_NODE_TYPE = "lead"

# Lifecycle tags. Exactly one is present on a lead at any time.
TAG_UNVERIFIED = "unverified"
TAG_CORROBORATED = "corroborated"
TAG_REFUTED = "refuted"
TAG_UNVERIFIABLE = "unverifiable"
LEAD_LIFECYCLE_TAGS = frozenset({
    TAG_UNVERIFIED, TAG_CORROBORATED, TAG_REFUTED, TAG_UNVERIFIABLE,
})

# Tags that make a node unsafe to ship to a defender / a client TIP. Kept
# separate from action_exports._DEFUSED_TAGS because the *reason* differs:
# defused = "real but noisy", unverified = "possibly not real at all".
NON_ACTIONABLE_TAGS = frozenset({TAG_UNVERIFIED, TAG_REFUTED, TAG_UNVERIFIABLE})

# Source markers written on lead nodes.
SOURCE_PARAMETRIC = "parametric_memory"
SOURCE_WEB_PREFIX = "web:"

# The pivot op enqueued for every fresh lead (drained like any other pivot).
VERIFY_LEAD_OP = "verify_lead"


def is_lead_source(source: str | None) -> bool:
    """True if ``source`` denotes context-pool provenance (memory or open web).

    Used by ``graph_mcp.add_node`` to decide whether the confidence cap and the
    forced ``lead`` type apply — i.e. this is the function that makes the tier
    boundary real rather than advisory.
    """
    s = (source or "").strip().lower()
    return s == SOURCE_PARAMETRIC or s.startswith(SOURCE_WEB_PREFIX)


def cap_lead_confidence(confidence: float | None) -> float:
    """Clamp a lead's confidence into ``[0.0, LEAD_CONFIDENCE_CAP]``."""
    try:
        c = float(confidence if confidence is not None else LEAD_CONFIDENCE_CAP)
    except (TypeError, ValueError):
        c = LEAD_CONFIDENCE_CAP
    return max(0.0, min(LEAD_CONFIDENCE_CAP, c))


def web_source(url: str) -> str:
    """Provenance marker for content fetched from ``url`` (``web:<host>``)."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        host = ""
    return f"{SOURCE_WEB_PREFIX}{host or 'unknown'}"


# ── Claim taxonomy ─────────────────────────────────────────────────────────
# recall_prior_knowledge forces the model to file its memory under one of these
# kinds. The taxonomy is what makes the DD deny-list mechanical: you cannot
# forbid "adverse media" in general, but you can refuse a claim_type.
CLAIM_TYPES: dict[str, str] = {
    # — generally useful —
    "identity": "who/what an identifier belongs to (handle → project, org, product)",
    "affiliation": "a subject's association with a group, org, project or platform",
    "naming": "the public name of a campaign, malware family, kit, cluster or tool",
    "technical_fingerprint": "a technical default/marker (cert CN pattern, JARM, path, header)",
    "registry_routing": "which authoritative registry/identifier system covers a subject "
                        "(jurisdiction, LEI, SIREN, CIK, ticker, former name)",
    "publication": "a public writeup/report/repo that likely documents the subject",
    "timeline": "an approximate date/period associated with the subject",
    "relationship": "a likely link between two subjects (same operator, parent/subsidiary)",
    # — permitted only where explicitly in scope —
    "reputation": "a published reputational signal about a non-natural entity",
}

# Claim kinds that are NEVER accepted from the context pool, in any vertical.
# These are determinations, not leads: no amount of corroboration by an OSINT
# source pool makes a model's memory a lawful basis for them.
GLOBALLY_FORBIDDEN_CLAIM_TYPES: frozenset[str] = frozenset({
    "criminal_record", "criminal", "conviction", "wrongdoing", "guilt",
    "health", "medical", "religion", "sexual_orientation", "political_opinion",
    "trade_union", "ethnicity", "biometric",
})

# DD (KYB) deny-list. verticals._DD_PROMPT_BLOCK already *tells* the agent not to
# generate adverse media about natural persons (GDPR art. 10 / art. 46 I&L). A
# prompt sentence is not a control: with `web_fetch` available the model could
# trivially produce exactly that. This set makes the prohibition mechanical —
# ctx_mcp refuses the call outright when vertical == "dd".
DD_FORBIDDEN_CLAIM_TYPES: frozenset[str] = frozenset({
    "adverse_media", "reputation", "litigation", "investigation", "allegation",
    "pep_status", "sanctions_opinion", "creditworthiness", "fraud",
}) | GLOBALLY_FORBIDDEN_CLAIM_TYPES

# OSINT deny-list. The OSINT lens is benign-by-default (verticals._OSINT_PROMPT_BLOCK)
# and is the vertical where a hallucinated link does the most human damage
# (doxxing-by-hallucination). Memory may propose *what an identifier is*, never
# *what a person did*.
OSINT_FORBIDDEN_CLAIM_TYPES: frozenset[str] = frozenset({
    "adverse_media", "allegation", "litigation", "fraud",
}) | GLOBALLY_FORBIDDEN_CLAIM_TYPES

_VERTICAL_CLAIM_DENYLIST: dict[str, frozenset[str]] = {
    "dd": DD_FORBIDDEN_CLAIM_TYPES,
    "osint": OSINT_FORBIDDEN_CLAIM_TYPES,
    "cti": GLOBALLY_FORBIDDEN_CLAIM_TYPES,
}


def normalise_claim_type(claim_type: str | None) -> str:
    return re.sub(r"[\s\-]+", "_", (claim_type or "").strip().lower())


def claim_type_denied(claim_type: str, vertical: str) -> Optional[str]:
    """Return a refusal reason if this claim kind is out of scope for the
    vertical, else ``None``.

    This is the mechanical counterpart to the legal guardrails written in the DD
    and OSINT prompt blocks — enforced at the tool boundary so it holds
    regardless of agent compliance.
    """
    ct = normalise_claim_type(claim_type)
    denied = _VERTICAL_CLAIM_DENYLIST.get((vertical or "cti").lower(),
                                          GLOBALLY_FORBIDDEN_CLAIM_TYPES)
    if ct in denied:
        if ct in GLOBALLY_FORBIDDEN_CLAIM_TYPES:
            return (f"claim_type '{ct}' is never accepted from the context pool: it is a "
                    "special-category / criminal-data determination, not a research lead")
        return (f"claim_type '{ct}' is out of scope in the '{vertical}' vertical "
                "(adverse-media / criminal-inference is a separate, legally-gated capability)")
    return None


# ── Corroboration ──────────────────────────────────────────────────────────
# A lead is only ever ratified by a *primary* tool — i.e. a source-pool tool
# that re-queries a third party. Corroborating a lead with another context-pool
# call would be circular (memory confirming memory), so ctx tools are refused.
_CONTEXT_TOOL_PREFIX = "mcp__ctx__"


def is_primary_evidence_tool(tool: str | None) -> bool:
    """True if ``tool`` is a source-pool tool that can ratify a lead.

    Accepts both the fully-qualified MCP name (``mcp__cti__crtsh_subdomains``)
    and the bare op name (``crtsh_subdomains``). Rejects context-pool tools and
    pure graph mutations — neither observes the outside world.
    """
    t = (tool or "").strip()
    if not t:
        return False
    if t.startswith(_CONTEXT_TOOL_PREFIX):
        return False
    if t.startswith("mcp__graph__"):
        return False
    return True


def corroboration_stats(nodes: Iterable[dict]) -> dict:
    """Corroboration telemetry over a graph's lead nodes.

    ``rate`` = corroborated / (corroborated + refuted + unverifiable + unverified).
    This is the **measurable hallucination thermometer**: it turns "the model
    might make things up" from a vague risk into a per-run, per-vertical,
    per-model number that EVAL_PROTOCOL can track and a code change can move.
    """
    total = corroborated = refuted = unverifiable = unverified = 0
    by_claim_type: dict[str, dict] = {}
    for n in nodes:
        if (n.get("type") or "") != LEAD_NODE_TYPE:
            continue
        total += 1
        tags = set(n.get("tags") or [])
        if TAG_CORROBORATED in tags:
            bucket = "corroborated"
            corroborated += 1
        elif TAG_REFUTED in tags:
            bucket = "refuted"
            refuted += 1
        elif TAG_UNVERIFIABLE in tags:
            bucket = "unverifiable"
            unverifiable += 1
        else:
            bucket = "unverified"
            unverified += 1
        ct = normalise_claim_type((n.get("metadata") or {}).get("claim_type")) or "unspecified"
        slot = by_claim_type.setdefault(
            ct, {"total": 0, "corroborated": 0, "refuted": 0,
                 "unverifiable": 0, "unverified": 0})
        slot["total"] += 1
        slot[bucket] += 1

    rate = round(corroborated / total, 3) if total else None
    return {
        "total_leads": total,
        "corroborated": corroborated,
        "refuted": refuted,
        "unverifiable": unverifiable,
        "unverified": unverified,
        "corroboration_rate": rate,
        "by_claim_type": by_claim_type,
    }


def split_leads(nodes: Iterable[dict]) -> tuple[list[dict], list[dict]]:
    """Partition a node list into ``(ratified_nodes, unratified_nodes)``.

    Dossiers and the PDF are read by humans, so unratified material is *shown*
    rather than dropped — but only under its own clearly-labelled heading, never
    mixed into the body where it would read as an established finding.

    The split is on :func:`is_actionable`, not on node type: a `lead` node is
    obviously unratified, but so is a typed node still carrying `unverified` /
    `refuted` / `unverifiable` (e.g. a domain the agent read on a blog and
    graphed before any source tool confirmed it). Partitioning on type alone
    would leave exactly those in the dossier body — which is the case this
    function exists to prevent.
    """
    leads, rest = [], []
    for n in nodes:
        (rest if is_actionable(n) else leads).append(n)
    return rest, leads


def leads_markdown_section(leads: list[dict], heading_level: str = "##") -> list[str]:
    """Render the leads section of a Markdown dossier as a list of lines.

    Shared by the OSINT and DD dossier renderers so the caveat wording — and the
    grouping by verdict — cannot drift between them.
    """
    if not leads:
        return []
    stats = corroboration_stats(leads)
    order = [
        (TAG_CORROBORATED, "Corroborated",
         "confirmed by a primary source tool and promoted where applicable"),
        (TAG_REFUTED, "Refuted",
         "a primary source contradicted the claim — recorded so the assumption is not retried"),
        (TAG_UNVERIFIABLE, "Unverifiable",
         "no available source could test the claim either way"),
        (TAG_UNVERIFIED, "Unverified",
         "never tested — treat as speculation only"),
    ]
    buckets: dict[str, list[dict]] = {k: [] for k, _, _ in order}
    for n in leads:
        tags = set(n.get("tags") or [])
        for key, _, _ in order:
            if key == TAG_UNVERIFIED:
                buckets[TAG_UNVERIFIED].append(n)
                break
            if key in tags:
                buckets[key].append(n)
                break

    L = [f"{heading_level} Leads (context pool — not established facts)", ""]
    rate = stats["corroboration_rate"]
    L.append(
        f"These {stats['total_leads']} item(s) came from the agent's prior knowledge or "
        "from open-web text, **not** from a source tool. They are excluded from all "
        "actionable exports (blocklist, detection rules, takedown, STIX). "
        f"Corroboration rate: **{rate if rate is not None else 'n/a'}** "
        f"({stats['corroborated']} corroborated / {stats['refuted']} refuted / "
        f"{stats['unverifiable']} unverifiable / {stats['unverified']} untested)."
    )
    L.append("")
    for key, label, blurb in order:
        items = buckets.get(key) or []
        if not items:
            continue
        L.append(f"**{label}** — _{blurb}_")
        L.append("")
        for n in items:
            md = n.get("metadata") or {}
            claim = str(n.get("value") or "").strip()
            # A typed-but-unratified node (a domain read off a blog post) shows
            # its type, so the reader can tell it apart from a prose claim.
            ntype = (n.get("type") or "")
            if ntype and ntype != LEAD_NODE_TYPE:
                claim = f"({ntype}) `{claim}`"
            bits = []
            if md.get("subject"):
                bits.append(f"subject: `{md['subject']}`")
            if md.get("claim_type"):
                bits.append(f"type: {md['claim_type']}")
            if md.get("verdict_evidence_tool"):
                bits.append(f"evidence: {md['verdict_evidence_tool']}"
                            + (f" → `{md['verdict_evidence_value']}`"
                               if md.get("verdict_evidence_value") else ""))
            suffix = f"  \n  <sub>{' · '.join(bits)}</sub>" if bits else ""
            L.append(f"- {claim}{suffix}")
        L.append("")
    return L


def is_actionable(node: dict) -> bool:
    """False for anything that must never reach a firewall, a TIP, or an abuse
    mailbox: raw ``lead`` nodes and any node still carrying a non-actionable
    lifecycle tag.

    Deliberately has **no** analyst override (unlike ``include_defused``): a
    defused node is real-but-noisy and an analyst may knowingly want it, whereas
    an unverified lead may simply not exist.
    """
    if (node.get("type") or "") == LEAD_NODE_TYPE:
        return False
    if set(node.get("tags") or []) & NON_ACTIONABLE_TAGS:
        return False
    return True


# ── Web-fetch safety (SSRF + size + scheme) ────────────────────────────────
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".localdomain", ".cluster.local")
# Cloud instance-metadata endpoints — the classic SSRF credential-theft target.
_BLOCKED_HOSTS = frozenset({
    "localhost", "metadata.google.internal", "metadata.goog",
    "instance-data", "metadata",
})

MAX_FETCH_BYTES = 200_000


def check_fetch_url(url: str) -> Optional[str]:
    """Return a refusal reason if ``url`` is unsafe to fetch, else ``None``.

    ``web_fetch`` turns the investigation agent into an HTTP client running
    inside the backend's network namespace, so this guards the classic SSRF
    targets: non-HTTP schemes, loopback / link-local / private / reserved
    addresses, and cloud metadata endpoints. Hostnames are checked
    syntactically here; the caller additionally resolves and re-checks the
    literal address before connecting.
    """
    u = (url or "").strip()
    if not u:
        return "empty url"
    try:
        p = urlparse(u)
    except Exception as e:
        return f"unparseable url: {e}"
    if (p.scheme or "").lower() not in _ALLOWED_SCHEMES:
        return f"scheme '{p.scheme}' not allowed (http/https only)"
    host = (p.hostname or "").lower()
    if not host:
        return "url has no host"
    if host in _BLOCKED_HOSTS or host.endswith(_BLOCKED_HOST_SUFFIXES):
        return f"host '{host}' is internal/metadata — refused"
    reason = check_fetch_host_address(host)
    if reason:
        return reason
    return None


def check_fetch_host_address(host_or_ip: str) -> Optional[str]:
    """Refusal reason if ``host_or_ip`` parses as a non-public IP, else ``None``.

    Called both on the URL's host (when it is a literal address) and on every
    address the host resolves to, so a public name pointing at 169.254.169.254
    is still refused.
    """
    try:
        addr = ipaddress.ip_address(host_or_ip)
    except ValueError:
        return None  # not a literal address — nothing to check here
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
        return f"address '{host_or_ip}' is private/loopback/link-local — refused (SSRF guard)"
    return None


# ── Enablement policy ──────────────────────────────────────────────────────
# The context pool changes agent behaviour, and `main` deploys straight to prod
# with EVAL_PROTOCOL gating CTI. So the default is deliberately asymmetric:
#
#   auto (default) → ON for osint + dd, OFF for cti
#   all / 1 / on   → ON everywhere (opt in after an eval run)
#   0 / off        → OFF everywhere (kill switch)
#
# OSINT and DD are where the value is (the OSINT lens runs on the CTI pool and is
# structurally blind to identity context; DD needs registry routing) and neither
# carries the byte-for-byte prompt invariant or the §4.5 budget cliff that CTI does.
_DEFAULT_CTX_VERTICALS = frozenset({"osint", "dd"})


def context_pool_enabled(vertical: str | None) -> bool:
    """True if the context pool is mounted for this vertical."""
    raw = (os.getenv("BOUNCE_CTX_ENABLED", "auto") or "auto").strip().lower()
    v = (vertical or "cti").lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on", "all"):
        return True
    if raw == "auto" or not raw:
        return v in _DEFAULT_CTX_VERTICALS
    # explicit comma-separated vertical list, e.g. "osint,dd"
    return v in {x.strip() for x in raw.split(",") if x.strip()}


def web_tools_enabled() -> bool:
    """True if the *networked* context tools (`web_search` / `web_fetch`) are
    available, on top of the always-free `recall_prior_knowledge`.

    Slice 1 of this feature (memory → lead → corroboration) needs no network at
    all: zero cost, zero latency, zero injection surface. Slice 2 adds the web,
    which is where the prompt-injection and determinism trade-offs live — so it
    is separately switchable and defaults ON only when the pool itself is on.
    """
    raw = os.getenv("BOUNCE_CTX_WEB")
    if raw is None or not raw.strip():
        return True
    return raw.strip().lower() in ("1", "true", "yes", "on")


def ctx_budget() -> int:
    """Max context-pool tool calls per investigation (0 = unlimited).

    Counted separately from BOUNCE_TOTAL_CTI_BUDGET so context calls never eat
    the source-pool budget the EVAL_PROTOCOL §4.5 bands are calibrated on — but
    bounded, so they cannot become an unmetered side channel either.
    """
    try:
        return max(0, int(os.getenv("BOUNCE_CTX_BUDGET", "12") or 12))
    except ValueError:
        return 12
