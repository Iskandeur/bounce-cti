"""Spawn Claude Code in headless mode to run an investigation."""
import asyncio
import datetime as _dt
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Optional
from .config import CLAUDE_BIN
from . import graph_store as gs
from . import seeds


# Valid extended-thinking effort levels accepted by the Claude CLI's --effort
# flag / CLAUDE_CODE_EFFORT_LEVEL env var. Anything outside this set is ignored
# (the CLI default applies). Mirrored by ALLOWED_EFFORTS in backend/main.py.
_VALID_EFFORTS = {"low", "medium", "high", "xhigh", "max"}

# Map a frontend model alias to the exact CLI model id. Aliases not listed pass
# through untouched (e.g. "sonnet"/"opus"/"haiku" resolve via the CLI's own
# latest-version aliasing).
_MODEL_ALIASES = {
    "opus-4.7": "claude-opus-4-7",
    "opus-4.8": "claude-opus-4-8",
}


# ── Claude-subscription quota detection ───────────────────────────────────
# When the subscription's rolling window is exhausted the Claude CLI signals
# it two ways, both handled here:
#   1. A structured stream-json event `{"type":"rate_limit_event",
#      "rate_limit":{"status":"rejected","resetsAt":<epoch>}}`. status is
#      "allowed"/"allowed_warning" on the normal informational events (one per
#      turn) — those MUST NOT halt; only a non-allowed status is exhaustion.
#   2. A human-readable string — the legacy "Claude AI usage limit
#      reached|<epoch>" marker, or newer phrasings like
#      "You've hit your limit · resets 1:50pm (UTC)".
# We scan stream-json events and stderr for any of these and capture the reset
# epoch so the UI can show "resumes in HH:MM:SS" and the global gate can refuse
# fresh spawns until then.
_QUOTA_RESET_RE = re.compile(
    r'Claude\s+(?:AI\s+)?usage\s+limit\s+reached\s*\|\s*(\d{10,})',
    re.IGNORECASE,
)
# Pull a reset epoch out of a json-dumped rate_limit_event, wherever the field
# lands. Accepts seconds (10-digit) or milliseconds (13-digit) — small
# durations like a retry_after of 60 won't match the digit floor.
_RESET_EPOCH_RE = re.compile(
    r'"(?:resets_?at|reset_?at|retry_?at)"\s*:\s*"?(\d{10,13})',
    re.IGNORECASE,
)
# Newer CLI builds print the reset time as a human-readable wall clock instead
# of an epoch, e.g. "You've hit your limit · resets 1:50pm (UTC)". The CLI
# reports this in UTC; we must anchor to UTC and NOT to the server's local
# timezone, otherwise the reset epoch (and therefore the UI countdown, which is
# reset_epoch − now) is off by the server↔UTC offset.
_RESET_CLOCK_RE = re.compile(
    r'reset(?:s|ting)?(?:\s+at)?\s+'
    r'(\d{1,2})(?::(\d{2}))?\s*([ap]\.?m\.?)?'      # hour[:min][am/pm]
    r'\s*\(?\s*(UTC|GMT)?\s*\)?',                    # optional zero-offset label
    re.IGNORECASE,
)


def _parse_reset_clock(text: str, now: Optional[float] = None) -> Optional[float]:
    """Parse a human-readable reset wall-clock time (e.g. 'resets 1:50pm (UTC)')
    into a unix epoch. The CLI reports the time in UTC, so we resolve it to the
    NEXT future occurrence of that HH:MM in UTC. This keeps the countdown
    correct for every viewer regardless of their local timezone — the bug being
    that a wall-clock string interpreted in the wrong referential yields a
    reset epoch that's off by the UTC offset. Returns None if no time is found."""
    if not text:
        return None
    m = _RESET_CLOCK_RE.search(text)
    if not m or m.group(1) is None:
        return None
    try:
        hour = int(m.group(1))
    except (TypeError, ValueError):
        return None
    minute = int(m.group(2)) if m.group(2) else 0
    ampm = (m.group(3) or "").lower().replace(".", "")
    if ampm == "pm" and hour < 12:
        hour += 12
    elif ampm == "am" and hour == 12:
        hour = 0
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return None
    now_dt = (_dt.datetime.now(_dt.timezone.utc) if now is None
              else _dt.datetime.fromtimestamp(now, _dt.timezone.utc))
    candidate = now_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now_dt:
        candidate += _dt.timedelta(days=1)
    return candidate.timestamp()
# rate_limit.status values that are informational and must NOT trigger a halt.
_RATE_LIMIT_OK_STATUSES = {"allowed", "allowed_warning", "warning", "ok", "active"}
# Quota-detection patterns. These are matched against the Claude CLI's
# stream-json events AND stderr, so they must be specific enough to avoid
# false positives from CTI tool responses (crt.sh / threatfox / VT free
# tier all return strings like "too many requests" / "rate limit" on a 429,
# which is NOT an Anthropic quota issue). The 2026-05-21 eval run measured
# 4/12 cases mis-flagged as quota_exceeded on the FIRST CTI tool call —
# diagnosed as the bare "too many requests" pattern matching a CTI 429.
_QUOTA_KEYWORDS = [
    re.compile(r'Claude\s+(?:AI\s+)?usage\s+limit\s+reached', re.IGNORECASE),
    re.compile(r'usage\s+limit\s+reached', re.IGNORECASE),
    re.compile(r'5[- ]?hour\s+(?:usage\s+)?limit', re.IGNORECASE),
    re.compile(r'\b(?:Anthropic|Claude)\s+plan\s+limit\b', re.IGNORECASE),
    re.compile(r'(?:Anthropic|Claude)\s+quota\s+exceeded', re.IGNORECASE),
    re.compile(r'(?:Anthropic|Claude)\s+rate\s+limit\s+reached', re.IGNORECASE),
    # Newer CLI builds surface a human-readable usage-limit string instead of
    # the "usage limit reached|<epoch>" marker, e.g.
    #   "You've hit your limit · resets 1:50pm (UTC)"
    #   "You've reached your usage limit"
    # These phrasings are CLI-specific; a CTI source 429 never says
    # "you've hit/reached your limit", so they don't reintroduce the
    # false-positive class removed below.
    re.compile(r"you'?ve\s+(?:hit|reached)\s+your\s+(?:usage\s+)?limit", re.IGNORECASE),
    re.compile(r'\bhit\s+your\s+usage\s+limit', re.IGNORECASE),
    # NB: bare "too many requests" / "quota exceeded" / "rate limit reached"
    # removed 2026-05-21 — they fire on CTI source 429s and tank
    # investigations on the FIRST tool call. The Claude CLI emits the
    # branded variants above when its own 5h budget is exhausted.
]


def _coerce_epoch(v) -> Optional[float]:
    """Coerce a resetsAt-style value to a unix-epoch-seconds float. Treats
    13-digit values as milliseconds. Returns None for junk / non-positive."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if f <= 0:
        return None
    if f > 1e12:  # milliseconds
        f /= 1000.0
    return f


def _detect_quota_error(text: str) -> tuple[bool, Optional[float], str]:
    """Inspect a chunk of text (CLI stream-json field, stderr line, …) and
    return (hit, reset_at_epoch_or_None, matched_phrase). hit=True means the
    text looks like a Claude-subscription quota exhaustion."""
    if not text:
        return (False, None, "")
    m = _QUOTA_RESET_RE.search(text)
    if m:
        try:
            return (True, float(m.group(1)), m.group(0))
        except ValueError:
            return (True, None, m.group(0))
    for pat in _QUOTA_KEYWORDS:
        m = pat.search(text)
        if m:
            # Best-effort: recover a reset epoch from a co-located resetsAt
            # field (present when the match came from a json-dumped event)…
            rm = _RESET_EPOCH_RE.search(text)
            reset_at = _coerce_epoch(rm.group(1)) if rm else None
            # …or, failing that, from a human-readable "resets 1:50pm (UTC)"
            # wall-clock string (newer CLI builds). Parsed as UTC so the
            # countdown lands in the right referential.
            if reset_at is None:
                reset_at = _parse_reset_clock(text)
            return (True, reset_at, m.group(0))
    return (False, None, "")


def _scan_event_for_quota(evt) -> tuple[bool, Optional[float], str]:
    """Walk a stream-json event payload (typically a dict) and look for a
    quota-exhaustion marker. Prefers the structured rate_limit_event status
    over text matching so a benign status="allowed" event never halts."""
    if isinstance(evt, dict) and evt.get("type") == "rate_limit_event":
        rl = evt.get("rate_limit") or evt.get("rateLimit") or evt
        if isinstance(rl, dict):
            status = str(rl.get("status", "")).strip().lower()
            if status and status not in _RATE_LIMIT_OK_STATUSES:
                reset_at = _coerce_epoch(
                    rl.get("resetsAt") or rl.get("resets_at")
                    or rl.get("reset_at") or rl.get("retryAt"))
                return (True, reset_at, f"rate_limit_event status={status}")
        # status allowed / missing → not a halt; fall through to the text scan
        # in case the payload also carries an explicit usage-limit string.
    try:
        blob = json.dumps(evt)
    except (TypeError, ValueError):
        blob = str(evt)
    return _detect_quota_error(blob)


# When the CLI reports quota exhaustion but we can't recover an explicit reset
# epoch (older text-only variants, or a rate_limit_event lacking resetsAt), we
# still need a future reset time — otherwise get_quota_state() treats a None
# `exhausted_until` as "not blocked" and every queued phase burns another
# failed spawn. Claude's window is ~5h; a 1h floor keeps the Resume affordance
# from being stuck forever while staying conservative.
_QUOTA_FALLBACK_COOLDOWN_S = float(
    os.environ.get("BOUNCE_QUOTA_FALLBACK_COOLDOWN_S", "3600")
)


# Global registry of running agent processes, keyed by investigation id.
# Used by stop_investigation() to kill a running agent on demand.
_running_procs: dict[str, asyncio.subprocess.Process] = {}


def stop_investigation(inv_id: str) -> bool:
    """Kill the running agent process for an investigation. Returns True if killed."""
    proc = _running_procs.pop(inv_id, None)
    if proc is None or proc.returncode is not None:
        return False
    try:
        import signal
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except Exception:
            pass
    return True


def _log(inv_id: str, kind: str, msg):
    with gs.conn() as c:
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv_id, kind, json.dumps({"kind": kind, "msg": msg}), time.time()))


def _finalise_quota_halt(inv_id: str, quota: dict) -> None:
    """Mark an investigation as halted by a Claude-subscription quota error.
    Stores the reset epoch on the investigation row, flips status to
    `quota_exceeded`, and emits a status_change event so the websocket
    clients refresh the sidebar + show the Resume affordance."""
    reset_at = quota.get("reset_at") if isinstance(quota, dict) else None
    msg = (quota.get("message") if isinstance(quota, dict) else "") or \
        "Claude subscription quota reached"
    try:
        gs.set_quota_reset_at(inv_id, reset_at)
    except Exception:
        pass
    gs.set_status(inv_id, "quota_exceeded")
    try:
        with gs.conn() as c:
            payload = {
                "kind": "status_change", "status": "quota_exceeded",
                "quota_reset_at": reset_at, "quota_message": str(msg)[:200],
            }
            c.execute(
                "INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                (inv_id, "status_change", json.dumps(payload), time.time()),
            )
    except Exception:
        pass


def quota_block_active() -> tuple[bool, Optional[float], Optional[str]]:
    """Return (blocked, reset_at, message) — True when a prior agent run
    reported a Claude usage-limit error and the reset epoch hasn't passed.
    Used by API entry points to refuse fresh spawns while we're cooling
    down, instead of burning more failed `claude -p` invocations."""
    try:
        s = gs.get_quota_state()
    except Exception:
        return (False, None, None)
    return (bool(s.get("exhausted")), s.get("exhausted_until"), s.get("message"))

ROOT = Path(__file__).resolve().parent.parent


def _get_called_cti_tools(inv_id: str) -> set:
    """Extract the set of CTI tool base names actually invoked during an investigation.

    Only counts tool_use blocks in assistant messages — ignores tool names that
    merely appear in the init event's available-tools list.
    """
    with gs.conn() as c:
        rows = c.execute(
            "SELECT payload FROM events WHERE investigation_id=?",
            (inv_id,)
        ).fetchall()
    tools = set()
    for (payload,) in rows:
        try:
            d = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            continue
        if d.get("kind") != "agent_assistant":
            continue
        for block in d.get("msg", {}).get("message", {}).get("content", []):
            if block.get("type") == "tool_use":
                name = block.get("name", "")
                if name.startswith("mcp__cti__"):
                    tools.add(name[len("mcp__cti__"):])
    return tools


def _count_cti_calls(inv_id: str) -> int:
    """Raw count of CTI tool_use blocks across the whole investigation (NOT
    deduplicated — every individual mcp__cti__* invocation counts once).

    Used by the pivot-drain loop to enforce a global call ceiling so total
    spend lands inside the EVAL_PROTOCOL §4.5 budget bands. A single agent
    turn can emit several parallel tool_use blocks, so this counts blocks,
    not turns — matching exactly how the eval scorer counts BD."""
    with gs.conn() as c:
        rows = c.execute(
            "SELECT payload FROM events WHERE investigation_id=?",
            (inv_id,)
        ).fetchall()
    n = 0
    for (payload,) in rows:
        try:
            d = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            continue
        if d.get("kind") != "agent_assistant":
            continue
        for block in d.get("msg", {}).get("message", {}).get("content", []):
            if block.get("type") == "tool_use" and \
               str(block.get("name", "")).startswith("mcp__cti__"):
                n += 1
    return n


def _get_called_tool_invocations(inv_id: str) -> set:
    """Like _get_called_cti_tools but returns (tool_name, primary_arg_str_lower).
    Used by the adaptive-followup logic to detect which (tool, value) pairs
    were actually invoked, so we don't re-trigger them."""
    with gs.conn() as c:
        rows = c.execute(
            "SELECT payload FROM events WHERE investigation_id=?",
            (inv_id,)
        ).fetchall()
    out: set = set()
    for (payload,) in rows:
        try:
            d = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            continue
        if d.get("kind") != "agent_assistant":
            continue
        for block in d.get("msg", {}).get("message", {}).get("content", []):
            if block.get("type") != "tool_use":
                continue
            name = block.get("name", "")
            if not name.startswith("mcp__cti__"):
                continue
            short = name[len("mcp__cti__"):]
            inp = block.get("input") or {}
            # Pick the first non-empty string-ish value as primary arg
            primary = ""
            for v in inp.values():
                if isinstance(v, (str, int)) and str(v).strip():
                    primary = str(v).strip().lower()
                    break
            out.add((short, primary))
    return out


def _adaptive_followup_targets(inv_id: str) -> list:
    """Inspect the current graph and return per-node Phase 3 gaps that would
    be high-leverage to fill. Adaptive: only emits tasks for nodes that
    actually exist in the graph; tools that have no API key configured are
    silently skipped (the source itself will degrade gracefully). Cap at 12
    to avoid Phase 2 storm.

    Returns: [(node_type, node_value, [missing_tool_call_strings], rationale)]
    """
    try:
        called = _get_called_tool_invocations(inv_id)
    except Exception:
        called = set()
    try:
        graph = gs.get_graph(inv_id)
    except Exception:
        return []

    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []

    def was_called(tool: str, value: str) -> bool:
        return (tool, str(value).lower()) in called

    targets = []
    seen_keys: set = set()  # dedup on (node_type, node_value)

    for n in nodes:
        ntype = (n.get("type") or "").lower()
        nvalue = n.get("value") or ""
        ntags = [t.lower() for t in (n.get("tags") or [])]
        md = n.get("metadata") or {}

        if not nvalue:
            continue
        key = (ntype, nvalue.lower())
        if key in seen_keys:
            continue

        # email → whoxy_reverse (skip institutional / registrar emails)
        if ntype == "email" and not any(t in ntags for t in ("privacy", "redacted", "institutional", "registrar")):
            try:
                from .hints import _is_private_email
                is_inst = _is_private_email(nvalue)
            except Exception:
                is_inst = False
            if not is_inst and not was_called("whoxy_reverse", nvalue):
                targets.append((ntype, nvalue, [f"whoxy_reverse(email=\"{nvalue}\")"],
                                 "registrant email never reverse-WHOISed"))
                seen_keys.add(key)
                continue

        # JARM → netlas_jarm + zoomeye_jarm
        if ntype == "jarm":
            missing = []
            if not was_called("netlas_jarm", nvalue):
                missing.append(f"netlas_jarm(\"{nvalue}\")")
            if not was_called("zoomeye_jarm", nvalue):
                missing.append(f"zoomeye_jarm(\"{nvalue}\")")
            if missing:
                targets.append((ntype, nvalue, missing,
                                 "JARM never multi-source pivoted (netlas/zoomeye)"))
                seen_keys.add(key)
                continue

        # favicon_hash → netlas_favicon + zoomeye_favicon
        if ntype == "favicon_hash":
            missing = []
            if not was_called("netlas_favicon", nvalue):
                missing.append(f"netlas_favicon(\"{nvalue}\")")
            if not was_called("zoomeye_favicon", nvalue):
                missing.append(f"zoomeye_favicon(\"{nvalue}\")")
            if missing:
                targets.append((ntype, nvalue, missing,
                                 "favicon hash never pivoted"))
                seen_keys.add(key)
                continue

        # cert with serial → certspotter_serial
        if ntype == "cert":
            serial = md.get("serial") or md.get("serial_number") or md.get("serialNumber")
            if serial and isinstance(serial, str) and not was_called("certspotter_serial", serial):
                targets.append((ntype, nvalue,
                                 [f"certspotter_serial(\"{serial}\")"],
                                 f"cert serial {serial[:24]}... never CT-cluster pivoted"))
                seen_keys.add(key)
                continue

        # Seed domain → certspotter_issuances + dom_fingerprints
        if ntype == "domain" and "seed" in ntags:
            missing = []
            if not was_called("certspotter_issuances", nvalue):
                missing.append(f"certspotter_issuances(domain=\"{nvalue}\", include_subdomains=True)")
            if missing:
                targets.append((ntype, nvalue, missing,
                                 "seed domain CT-history never enriched via CertSpotter"))
                seen_keys.add(key)
                continue

        # Non-defused IP → abuseipdb + criminalip
        if ntype == "ip" and not any(t in ntags for t in ("cdn", "parking", "sinkhole", "dyndns")):
            missing = []
            if not was_called("abuseipdb_check", nvalue):
                missing.append(f"abuseipdb_check(\"{nvalue}\")")
            if not was_called("criminalip_ip", nvalue):
                missing.append(f"criminalip_ip(\"{nvalue}\")")
            if missing:
                targets.append((ntype, nvalue, missing,
                                 "non-CDN IP never IP-rep cross-checked"))
                seen_keys.add(key)
                continue

        # URL → dom_fingerprints
        if ntype == "url" and not was_called("dom_fingerprints", nvalue):
            targets.append((ntype, nvalue, [f"dom_fingerprints(url=\"{nvalue}\")"],
                             "URL DOM never fingerprinted"))
            seen_keys.add(key)
            continue

        # URL with a known page_title (from urlscan/dom_fingerprints) → urlscan
        # title pivot. THIS IS THE KIT-CLUSTER EXPANSION PIVOT — when kits
        # share an exact <title> string, they're almost always the same
        # operator. The agent often graphs the title in URL metadata but
        # never pivots on it (case study 52d2091f2ea2: 37 sibling phishing
        # domains found ONLY after the user manually asked for an exhaustive
        # map). Force it mechanically.
        if ntype == "url":
            page_title = (md.get("page_title") or md.get("title") or "").strip()
            if page_title and len(page_title) >= 4 and not was_called(
                "urlscan_search", f'page.title:"{page_title}"'.lower()
            ):
                # Cheap heuristic: skip very generic titles ("Home", "Login")
                # that would over-fan-out. Anything ≥ 4 chars and not on the
                # blocklist is worth a pivot.
                generic = {"home", "login", "index", "page", "site", "untitled",
                           "404 not found", "403 forbidden", "welcome",
                           "default web site page", "test page"}
                if page_title.lower() not in generic:
                    targets.append((ntype, nvalue,
                                     [f'urlscan_search("page.title:\\"{page_title}\\"", size=200)'],
                                     f"page title '{page_title[:40]}' never pivoted via urlscan — "
                                     f"strongest cluster-expansion signal for kit-templated phishing"))
                    seen_keys.add(key)
                    continue

        # title_hash → urlscan title pivot (dom_fingerprints emits these for
        # phishing kits). Same rationale as the URL page_title rule above,
        # but for nodes where the canonical fingerprint is the title hash
        # itself (rare, but emitted by some sources).
        if ntype == "title_hash":
            # Title-hash node value is either an SHA1 (hash) or the literal
            # title string depending on emitter. Prefer metadata.title if
            # present; otherwise treat the value as the literal title.
            title = (md.get("title") or md.get("page_title") or nvalue).strip()
            if title and len(title) >= 4 and not was_called(
                "urlscan_search", f'page.title:"{title}"'.lower()
            ):
                targets.append((ntype, nvalue,
                                 [f'urlscan_search("page.title:\\"{title}\\"", size=200)'],
                                 f"title_hash '{title[:40]}' never expanded into sibling cluster"))
                seen_keys.add(key)
                continue

        # tracking_id → urlscan tracker pivot (GA / GTM / FB Pixel /
        # Yandex / Hotjar / Clarity). Same operator typically reuses the
        # same tracker across kit deployments — strong cluster signal.
        if ntype == "tracking_id" and not was_called("urlscan_search", nvalue.lower()):
            targets.append((ntype, nvalue,
                             [f'urlscan_search("page.html:{nvalue}", size=100)'],
                             f"tracking ID {nvalue} never pivoted to find sibling pages"))
            seen_keys.add(key)
            continue

    # IP-seed reverse-DNS → TXT/MX cross-reference (graph-level).
    # Case 10 (Contagious Interview): reverse_dns(37.211.126.117) surfaces
    # `lianxinxiao.com`; the canonical pivot is dns_resolve(lianxinxiao.com,
    # "TXT") + dns_resolve(lianxinxiao.com, "MX") to cross-reference siblings
    # (this is the ONLY pivot path to blocknovas.com). The hint_for_reverse_dns
    # already nudges, but the agent ignored it on the 2026-05-05 + 2026-05-06
    # runs. Mechanical enforcement: when the seed is an IP, look for any
    # reverse_dns hostname-shaped node attached to the seed IP and force the
    # TXT/MX dns_resolve pair if not already called.
    seed_ip = None
    for n in nodes:
        if (n.get("type") or "").lower() == "ip" and \
           "seed" in [t.lower() for t in (n.get("tags") or [])]:
            seed_ip = n.get("value") or ""
            break
    if seed_ip:
        # Find domains/subdomains sourced from reverse_dns or with PTR-shaped
        # provenance (mnemonic_pdns, virustotal_resolutions_ip also count —
        # any non-CDN co-resolver that hasn't had TXT/MX dug). Cap to 3.
        cdn_hostname_subs = ("cloudfront", "amazonaws", "googleusercontent",
                              "fastly", "akamai", "azure-edge", "googleapis",
                              "cloudflare", "1e100.net", "akamaitechnologies")
        candidate_hosts: list[str] = []
        for n in nodes:
            if (n.get("type") or "").lower() != "domain":
                continue
            v = (n.get("value") or "").strip().lower()
            if not v or any(s in v for s in cdn_hostname_subs):
                continue
            tags = [str(t).lower() for t in (n.get("tags") or [])]
            if any(t in tags for t in ("cdn", "parking", "sinkhole", "dyndns",
                                         "shared_hosting")):
                continue
            # Skip the seed itself if (somehow) the seed is also a domain
            if "seed" in tags:
                continue
            if v not in candidate_hosts:
                candidate_hosts.append(v)
        for v in candidate_hosts[:3]:
            # The hint expects a SECOND dns_resolve specifying record type;
            # the dns_resolve tool wrapper accepts a `record` arg. Two calls
            # per host: TXT and MX.
            calls_needed = []
            txt_called = any(
                tool == "dns_resolve" and v in arg and "txt" in arg
                for (tool, arg) in called
            )
            mx_called = any(
                tool == "dns_resolve" and v in arg and "mx" in arg
                for (tool, arg) in called
            )
            if not txt_called:
                calls_needed.append(f'dns_resolve("{v}", record="TXT")')
            if not mx_called:
                calls_needed.append(f'dns_resolve("{v}", record="MX")')
            if calls_needed:
                key_txtmx = ("domain", f"{v}::txtmx_xref")
                if key_txtmx in seen_keys:
                    continue
                targets.append(("domain", v, calls_needed,
                                 f"reverse_dns / pdns surfaced '{v}' on seed IP "
                                 f"{seed_ip} but TXT/MX cross-reference never run "
                                 f"(canonical Contagious-Interview pivot — "
                                 f"lianxinxiao.com → blocknovas.com)"))
                seen_keys.add(key_txtmx)

    # Seed-domain DOM fingerprint pivot (graph-level): cases where the seed
    # is a phishing/infostealer/smishing/fronted-C2 domain need
    # dom_fingerprints called on the seed itself to extract favicon/title/
    # tracking-id markers that then cluster-pivot. The per-node URL branch
    # only fires for explicit URL nodes, so the seed-domain itself was never
    # DOM-fingerprinted on Cases 6 (LummaC2 About-Cats), 9 (Tycoon 2FA), 11
    # (Smishing Triad), 12 (ClearFake). Mechanical enforcement: if the
    # working_hypothesis category looks like a phishing/scam class, force
    # dom_fingerprints(url=https://<seed>/) once. We also fire when no
    # working_hypothesis is set yet but the seed is a domain — the cost is
    # one tool call and it's defensive.
    cluster_categories = {
        "phishing_kit", "phishing_kit_cluster", "smishing_hub", "smishing",
        "infostealer", "fronted_c2", "drainer_kit", "traffer_or_tds",
    }
    # Surface the working_hypothesis category if present
    wh_category: str | None = None
    for n in nodes:
        if (n.get("type") or "").lower() != "report":
            continue
        v = (n.get("value") or "").lower()
        if v == "working_hypothesis" or v.startswith("working_hypothesis"):
            md = n.get("metadata") or {}
            wh_category = (md.get("category") or md.get("candidate_category") or "").lower()
            break
    seed_domain_for_dom = None
    for n in nodes:
        if (n.get("type") or "").lower() == "domain" and \
           "seed" in [t.lower() for t in (n.get("tags") or [])]:
            seed_domain_for_dom = n.get("value") or ""
            break
    # Fire if (hypothesis is cluster-class) OR (we have NO hypothesis and seed
    # is a domain — defensive). dom_fingerprints is cheap and idempotent.
    if seed_domain_for_dom and (
        (wh_category in cluster_categories) or (wh_category is None)
    ):
        seed_url = f"https://{seed_domain_for_dom}/"
        already = any(
            tool == "dom_fingerprints" and (
                seed_domain_for_dom.lower() in arg or seed_url.lower() in arg
            )
            for (tool, arg) in called
        )
        if not already:
            key_dom = ("domain", f"{seed_domain_for_dom.lower()}::seed_dom")
            if key_dom not in seen_keys:
                rationale = (
                    f"seed domain never DOM-fingerprinted "
                    f"(category={wh_category or 'unset'}) — extracts "
                    f"favicon/title/tracking-id markers that drive kit-cluster "
                    f"expansion (LummaC2/Tycoon/Smishing-class pivot)"
                )
                targets.append(("domain", seed_domain_for_dom,
                                 [f'dom_fingerprints(url="{seed_url}")'],
                                 rationale))
                seen_keys.add(key_dom)

    # All-CDN seed-domain branch (graph-level, after the per-node loop):
    # when every IP node in the graph is CDN-tagged (Cloudflare front in front
    # of the seed), the only way to find the origin is the cert-CN unmask.
    # R14 in SYSTEM_PROMPT mandates this but is read-and-ignored (Cases 11 + 12
    # missed it across two consecutive runs). Mechanical enforcement here.
    seed_domain = None
    for n in nodes:
        if (n.get("type") or "").lower() == "domain" and \
           "seed" in [t.lower() for t in (n.get("tags") or [])]:
            seed_domain = n.get("value") or ""
            break
    if seed_domain:
        ip_nodes = [n for n in nodes if (n.get("type") or "").lower() == "ip"]
        non_cdn_ips = [n for n in ip_nodes
                       if "cdn" not in [t.lower() for t in (n.get("tags") or [])]]
        # Has the agent established the seed has cert evidence (so a cert-CN
        # query would actually find something)? Either crtsh/certspotter was
        # called on the seed, or a `cert` / `cert_serial` node references it.
        cert_evidence = any(
            tool in ("crtsh_subdomains", "crtsh_query", "crtsh_serial",
                      "certspotter_issuances", "certspotter_serial")
            and seed_domain.lower() in arg
            for (tool, arg) in called
        )
        # Fire the cert-CN unmask when:
        #   (a) classic all-CDN case (≥1 IP, all tagged cdn), OR
        #   (b) the seed has 0 IP nodes but cert evidence exists (defensive —
        #       Case 12 ClearFake on 2026-05-05: agent did crtsh but never
        #       dns_resolve, so ip_nodes was empty and the original branch
        #       never triggered).
        ip_branch_fires = (ip_nodes and not non_cdn_ips) or \
                          (not ip_nodes and cert_evidence)
        if ip_branch_fires:
            shodan_called_with_cn = any(
                "ssl.cert.subject.cn" in arg
                for (tool, arg) in called if tool == "shodan_search"
            )
            onyphe_called_with_cn = any(
                "tls.cert.subject.commonname" in arg
                for (tool, arg) in called if tool == "onyphe_datascan"
            )
            cn_unmask_calls = []
            if not shodan_called_with_cn:
                cn_unmask_calls.append(
                    f"shodan_search(\"ssl.cert.subject.CN:\\\"{seed_domain}\\\"\")"
                )
            if not onyphe_called_with_cn:
                cn_unmask_calls.append(
                    f"onyphe_datascan(\"tls.cert.subject.commonname:\\\"{seed_domain}\\\"\")"
                )
            key_unmask = ("domain", f"{seed_domain.lower()}::cn_unmask")
            if cn_unmask_calls and key_unmask not in seen_keys:
                targets.append(("domain", seed_domain, cn_unmask_calls,
                                 "seed resolves only to CDN — origin unmask via cert CN "
                                 "required (R14, canonical Cloudflare-defuse)"))
                seen_keys.add(key_unmask)

    # Reverse-IP / pdns adaptive for non-CDN IPs that VT contacted_ips /
    # vt_communicating_files surfaced from hash or domain seeds. Case 3
    # (Bumblebee→Akira on 2026-05-06) hit F-PIVOT-MISS::reverse_ip_seo_decoy
    # because the agent stopped at "contacted IP 109.205.195.211" without
    # calling virustotal_resolutions_ip on it — the canonical pivot path to
    # the SEO-poison decoy cluster (angryipscanner.org, axiscamerastation.org,
    # ip-scanner.org). Mechanical enforcement: for the FIRST 3 non-CDN IPs
    # in the graph that haven't been reverse-PDNS pivoted, queue it.
    cdn_ip_tags = ("cdn", "cloudflare", "cloudfront", "akamai", "fastly",
                    "google_cloud", "aws", "azure", "anycast", "google")
    candidate_ips: list[str] = []
    for n in nodes:
        if (n.get("type") or "").lower() != "ip":
            continue
        v = (n.get("value") or "").strip()
        if not v:
            continue
        tags = [str(t).lower() for t in (n.get("tags") or [])]
        if any(t in tags for t in cdn_ip_tags):
            continue
        # Skip the seed IP itself — its rev-pdns is already in mandatory list
        if "seed" in tags:
            continue
        if v not in candidate_ips:
            candidate_ips.append(v)
    for v in candidate_ips[:3]:
        rev_called = any(
            tool in ("virustotal_resolutions_ip", "vt_resolutions_ip",
                      "mnemonic_pdns")
            and v in arg for (tool, arg) in called
        )
        if rev_called:
            continue
        key_revip = ("ip", f"{v}::rev_pdns")
        if key_revip in seen_keys:
            continue
        targets.append(("ip", v,
                         [f'virustotal_resolutions_ip("{v}")'],
                         f"non-CDN IP '{v}' surfaced by VT-contacted or "
                         f"reverse-DNS but never reverse-pdns'd "
                         f"(canonical SEO-decoy / co-resident cluster pivot — "
                         f"Bumblebee→Akira Case 3, SocGholish Case 7)"))
        seen_keys.add(key_revip)

    # Cap to 20 — Phase 2 should be focused, but cluster-class hypotheses
    # (phishing_kit_cluster + smishing_hub + drainer_kit) often surface
    # 8-15 cert/JARM/favicon/title/tracking_id pivots. 12 was too tight and
    # caused premature truncation; 20 still bounds the prompt size while
    # allowing the full cluster fan-out to fit.
    return targets[:20]


def _is_parked(inv_id: str) -> bool:
    """Check if the seed is parked / blackholed / sinkholed in a way that
    short-circuits phase 2 + hypothesis + follow-up.

    Returns True for: parking | blackhole | monitoring sinkhole.
    Returns False for: le_seized (LE takedown — we still want the full
    historical workflow on it, so phases proceed).
    """
    try:
        g = gs.get_graph(inv_id)
        nodes = g.get("nodes", [])
        # LE-takedown seeds keep the FULL historical workflow even when they are
        # sinkholed AND co-hosted with parking landers. The exemption must be
        # investigation-wide, not a per-node `continue`: Case 6 (le_seized
        # LummaC2 seed `rugtou.shop`) was wrongly short-circuited after 3 calls
        # because a co-resident parking-lander IP (172.234.24.211, tagged
        # `parking`) tripped the loop below before the seed's own le_seized tag
        # could exempt it. Check the seed first and bail out of the whole check.
        for n in nodes:
            if "seed" not in [t.lower() for t in (n.get("tags") or [])]:
                continue
            stags = [t.lower() for t in (n.get("tags") or [])]
            smd = n.get("metadata") or {}
            if "le_seized" in stags or (smd.get("sinkhole_kind") or "").lower() == "le_seized":
                return False
        for n in nodes:
            tags = [t.lower() for t in (n.get("tags") or [])]
            md = n.get("metadata") or {}
            if "parking" in tags or "blackhole" in tags:
                return True
            if "sinkhole" in tags:
                # LE-seized sinkholes have historical value — keep working.
                if "le_seized" in tags:
                    continue
                if (md.get("sinkhole_kind") or "").lower() == "le_seized":
                    continue
                return True
    except Exception:
        pass
    return False


def _has_lessons_learned(inv_id: str) -> bool:
    """True iff the investigation already has a `lessons_learned` report node."""
    try:
        g = gs.get_graph(inv_id)
        for n in g.get("nodes", []):
            if (n.get("type") or "").lower() == "report" and \
               (n.get("value") or "").lower() == "lessons_learned":
                return True
    except Exception:
        pass
    return False


def _enforce_summary_completeness(inv_id: str) -> None:
    """Mechanical post-process to fill the investigation_summary's ioc_list
    and discriminating_markers from graph state. The model paraphrases the
    runner's MUST-COPY-VERBATIM marker block ~50% of the time even after
    explicit instructions — measured on 2026-05-06 (Cases 5, 7, 9, 10, 11
    all RQ ≤ 40 despite the markers being available in the graph). This
    helper guarantees the markers land in the metadata blob where the
    scorer, UI, and shared-view all look.

    Idempotent; additive (never removes agent prose). Safe to call multiple
    times across phases — gs.add_node merges metadata for duplicate keys.
    """
    try:
        g = gs.get_graph(inv_id)
    except Exception:
        return
    nodes = g.get("nodes", []) or []
    summary = None
    for n in nodes:
        if (n.get("type") or "").lower() == "report" and \
           (n.get("value") or "").lower() == "investigation_summary":
            summary = n
            break
    if summary is None:
        return

    ioc_types = {"ip", "domain", "subdomain", "hash", "sha256", "sha1", "md5",
                  "email", "url", "wallet_address"}
    ioc_list_canonical: list[str] = []
    seen_ioc: set = set()
    for n in nodes:
        nt = (n.get("type") or "").lower()
        if nt not in ioc_types:
            continue
        nv = (n.get("value") or "").strip()
        if not nv:
            continue
        tags = [str(t).lower() for t in (n.get("tags") or [])]
        if "defused" in tags or "benign" in tags or "vendor_site" in tags:
            continue
        if nv.lower() in seen_ioc:
            continue
        seen_ioc.add(nv.lower())
        ioc_list_canonical.append(nv)

    marker_set: list[str] = []
    seen_markers: set = set()

    def _add_marker(s):
        if not s or not isinstance(s, str):
            return
        s = s.strip()
        if not s or len(s) > 200:
            return
        key = s.lower()
        if key in seen_markers:
            return
        seen_markers.add(key)
        marker_set.append(s)

    marker_field_keys = ("cert_serial", "cert_sha1", "cert_subject_cn",
                          "subject_cn", "common_name", "jarm",
                          "favicon_hash", "favicon_mmh3",
                          "registrant_email", "registrant", "registrar",
                          "http_title", "page_title", "title",
                          "issuer_o", "asn", "as_org",
                          "file_name", "meaningful_name", "tracking_id")
    marker_node_types = {"cert", "cert_cn", "cert_serial", "cert_sha1",
                          "jarm", "favicon_hash", "title_hash", "tracking_id",
                          "email", "registrar", "asn", "person", "actor",
                          "malware", "ransomware", "framework", "kit",
                          "phishing_kit"}
    for n in nodes:
        md = n.get("metadata") or {}
        for k in marker_field_keys:
            v = md.get(k)
            if isinstance(v, str):
                _add_marker(v)
        nt = (n.get("type") or "").lower()
        nv = (n.get("value") or "").strip()
        if nt in marker_node_types and nv:
            _add_marker(nv)
        for t in (n.get("tags") or []):
            if isinstance(t, str) and len(t) >= 32 and \
               re.match(r"^[a-f0-9]+$", t):
                _add_marker(t)

    if not ioc_list_canonical and not marker_set:
        return

    existing_md = summary.get("metadata") or {}
    existing_iocs = existing_md.get("ioc_list") or []
    if not isinstance(existing_iocs, list):
        existing_iocs = [str(existing_iocs)]
    existing_iocs_set = {str(x).lower() for x in existing_iocs
                         if isinstance(x, str)}
    for v in ioc_list_canonical:
        if v.lower() not in existing_iocs_set:
            existing_iocs.append(v)
            existing_iocs_set.add(v.lower())

    existing_markers = existing_md.get("discriminating_markers") or []
    if not isinstance(existing_markers, list):
        existing_markers = [str(existing_markers)]
    existing_marker_set = {str(x).lower() for x in existing_markers
                           if isinstance(x, str)}
    for m in marker_set:
        if m.lower() not in existing_marker_set:
            existing_markers.append(m)
            existing_marker_set.add(m.lower())

    patched = {
        **existing_md,
        "ioc_list": existing_iocs,
        "discriminating_markers": existing_markers,
    }
    try:
        gs.add_node(inv_id, "report", "investigation_summary",
                     metadata=patched, source="runner_enforce",
                     tags=list(set((summary.get("tags") or []) + ["report"])))
        _log(inv_id, "summary_completeness_enforced", {
            "ioc_list_size": len(existing_iocs),
            "discriminating_markers_size": len(existing_markers),
        })
    except Exception as e:
        _log(inv_id, "summary_completeness_error",
             {"error": str(e)[:200]})


# Global ledger of agent retrospectives. Each line is a JSON object with the
# investigation context + the metadata the agent wrote on the lessons_learned
# node. Append-only; an operator reads it directly (or through the new
# /api/admin/lessons_learned endpoint) to spot recurring blockers, missing
# tools, or suggested codebase improvements.
LESSONS_LEDGER_PATH = ROOT / "data" / "lessons_learned.jsonl"


def _append_lessons_ledger(inv_id: str, seed_type: str, seed_value: str,
                            model: str) -> None:
    """Read the lessons_learned node off the graph and append it to the
    project-wide JSONL ledger. Silently no-ops if the agent didn't write one
    or if the file system rejects the write — this is best-effort feedback,
    not a transactional state."""
    try:
        g = gs.get_graph(inv_id)
    except Exception as e:
        _log(inv_id, "lessons_ledger_skip", {"reason": "graph_read_failed",
                                              "error": str(e)[:200]})
        return
    node = None
    for n in g.get("nodes", []):
        if (n.get("type") or "").lower() == "report" and \
           (n.get("value") or "").lower() == "lessons_learned":
            node = n
            break
    if node is None:
        _log(inv_id, "lessons_ledger_skip", {"reason": "no_lessons_node"})
        return
    md = node.get("metadata") or {}
    # Quick stats so a reviewer can sort by "investigation size" / "had errors".
    n_nodes = len(g.get("nodes", []))
    n_edges = len(g.get("edges", []))
    entry = {
        "ts":                 time.time(),
        "investigation_id":   inv_id,
        "seed_type":          seed_type,
        "seed_value":         seed_value,
        "model":              model,
        "node_count":         n_nodes,
        "edge_count":         n_edges,
        "blockers":           md.get("blockers") or [],
        "missing_capabilities": md.get("missing_capabilities") or [],
        "suggestions":        md.get("suggestions") or [],
        "noteworthy":         md.get("noteworthy") or [],
        "self_critique":      md.get("self_critique") or "",
    }
    try:
        LESSONS_LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LESSONS_LEDGER_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _log(inv_id, "lessons_ledger_appended", {
            "path": str(LESSONS_LEDGER_PATH),
            "blockers": len(entry["blockers"]),
            "suggestions": len(entry["suggestions"]),
        })
    except Exception as e:
        _log(inv_id, "lessons_ledger_error", {"error": str(e)[:300]})


def _missing_mandatory_tools(seed_type: str, seed_value: str, called: set) -> list:
    """Return list of call examples for mandatory tools not yet called.

    The per-seed-type mandatory-tool spec lives in the seed registry
    (``backend/seeds.mandatory_tools``); see the per-builder comments there for
    the case-by-case rationale behind each tool. command_line / unknown seed
    types have no IOC-level mandatory tools — their prompt drives the per-IOC
    pivots once embedded indicators are graphed.
    """
    missing = []
    for tool_name, call_example in seeds.mandatory_tools(seed_type, seed_value):
        if tool_name not in called:
            missing.append(call_example)
    return missing


def _win_to_wsl(path: str) -> str:
    """C:\\Users\\foo → /mnt/c/Users/foo (no-op if already unix)."""
    s = str(path).replace("\\", "/")
    if len(s) >= 2 and s[1] == ":":
        return "/mnt/" + s[0].lower() + s[2:]
    return s


def _mcp_python() -> str:
    """Return the Python executable in a form that WSL claude can invoke.

    - On Windows (os.name=='nt'): convert to /mnt/c/... so WSL runs it via interop.
    - On WSL/Linux: use sys.executable directly.
    """
    exe = sys.executable
    if os.name == "nt":
        return _win_to_wsl(exe)
    return exe


def _mcp_launcher() -> str:
    """Absolute path to run_mcp.py.

    When on Windows: return the Windows path (C:\\...) because WSL interop
    executes python.exe with the Windows path as-is. The WSL→Win path test
    confirmed that Windows Python can open C:/... paths passed from WSL.
    When on Linux/WSL: return the unix path.
    """
    p = ROOT / "run_mcp.py"
    # Use forward slashes for the Windows path — python.exe accepts them
    return str(p).replace("\\", "/")


def _write_mcp_config(inv_id: str) -> Path:
    """Write a per-investigation mcp.json with correct paths for WSL claude.

    Uses run_mcp.py (a standalone launcher) so we don't need env-var PYTHONPATH tricks.
    The Python exe is converted to a WSL-accessible path when running on Windows.
    """
    python = _mcp_python()
    launcher = _mcp_launcher()

    # Pass minimal env: only what the MCP server actually needs.
    # run_mcp.py hard-codes the PYTHONPATH via os.path so no conversion needed.
    base_env = {
        k: v for k, v in os.environ.items()
        if k in ("HOME", "PATH", "TEMP", "TMP", "USERPROFILE", "APPDATA",
                 "LOCALAPPDATA", "SYSTEMROOT", "WINDIR", "COMSPEC",
                 "VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_DEFAULT_ENV",
                 # API keys
                 "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "ONYPHE_API_KEY",
                 "SHODAN_API_KEY", "OTX_API_KEY")
    }
    # Load .env file values explicitly so they are available to MCP servers
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in base_env:
                    base_env[k.strip()] = v.strip()

    cfg = {
        "mcpServers": {
            "graph": {
                "command": python,
                "args": [launcher, "graph_mcp"],
                "env": {**base_env, "BOUNCE_INV_ID": inv_id},
            },
            "cti": {
                "command": python,
                "args": [launcher, "cti_mcp"],
                "env": base_env,
            },
        }
    }
    p = ROOT / "data" / f"mcp-{inv_id}.json"
    p.write_text(json.dumps(cfg, indent=2))
    return p

SYSTEM_PROMPT = """You are Bounce-CTI, an autonomous CTI investigation agent.
Your ONLY job is to call MCP tools to build an investigation graph. You have no filesystem access.

══════════════════════════════════════════════
ABSOLUTE RULES — never break these
══════════════════════════════════════════════
R1. EVERY piece of information you find MUST become a node and/or edge via add_node/add_edge.
    Never keep findings in your text. If you found it, graph it.
R2. ALWAYS call defuse(kind, value) before pivoting on any IP or NS.
    defuse() returns {tags, reasons, sinkhole_kind, should_stop_pivot}.
      - If should_stop_pivot=true → tag the node with the returned tags, add a note in
        metadata (defuse_reason, sinkhole_kind), then STOP pivoting on it. Still
        graph the node itself.
      - If sinkhole_kind=="le_seized" → defuse returns should_stop_pivot=false on
        purpose: keep pivoting BUT only on HISTORICAL sources (virustotal_resolutions_*,
        wayback, threatfox_search, virustotal_communicating_files). Skip live infra
        chasing — the live IP is just the takedown sinkhole.
      - When RDAP exposes a registrant email / org / registrar field, pass it to
        defuse() as defuse(kind, value, registrant=<email_or_org>, registrar=<registrar>)
        so LE-seizure markers are caught even when the resolved IP isn't on the
        sinkhole list yet.
R3. Only use MCP tools (mcp__graph__* and mcp__cti__*). Do not attempt to read files, run commands, or search the web.
R4. Budget (yield-based, not flat cap) — STRICTLY ENFORCED:
    Soft-cap = 60 tool calls (the PURPOSE target for fast-triage).
    Hard-cap = 90 tool calls (after which you MUST finalize: SELF_CRITIQUE → REPORT).

    BEFORE call N=61 and EVERY 5 calls thereafter, you MUST do BOTH of these
    in the same turn before any further pivots:

      1. Call queue_status() to confirm pending > 0 (otherwise STOP).
      2. add_node("report", "budget_extension_<N>", metadata={
           "reason": "<one specific yield, e.g. last 5 calls produced 2 JARMs + 1 cert>",
           "calls_so_far": <N>,
           "queue_pending": <from queue_status>,
           "discriminating_fingerprints_last5": <count of new
              jarm/favicon_hash/cert_serial/tracking_id/wallet_address/email/non-CDN ip
              added since the previous budget_extension or start>
         })
         If discriminating_fingerprints_last5 == 0, you DO NOT continue — stop here
         and go to SELF_CRITIQUE.

    SKIPPING the budget_extension log is a hard violation of R4 and degrades the
    eval BD score from 100 to 50. Don't be lazy here — it's literally one add_node
    call before continuing.
R5. ALWAYS set source= to the API name that produced the data (e.g. "virustotal", "crtsh", "rdap", "dns").
R6. ALWAYS add edges between nodes. A node with no edges is useless to the analyst.
R7. Steps marked MANDATORY must be executed. Do NOT skip threat intel (STEP 6), malware hash lookups (communicating_files), or the report node (STEP 8).
R8. JARM pivot rule: if you extract a JARM fingerprint from ANY source (VT, Onyphe, Shodan), you MUST call shodan_search("ssl.jarm:<jarm>") to find related infrastructure. This is one of the highest-value pivots.
R9. MANDATORY: virustotal_communicating_files MUST be called for EVERY investigation (domain or IP seed). This is the primary way to discover malware samples communicating with the indicator. Skipping it produces an incomplete investigation. Call it in STEP 3 a3 (domain) or STEP 4 a (IP).
R10. Execute ALL workflow steps in order. Do not stop early because the graph "looks complete". The investigation is only complete when the report node (STEP 8/7) is written.
R11. EVIDENCE-BASED CONCLUSIONS ONLY. The `threat_assessment` field MUST default to "benign".
    You may only assign "suspicious" / "likely_malicious" / "malicious" if at least ONE of these
    concrete, direct-evidence conditions is met, AND you cite the exact source+value in key_findings:
      • virustotal_*.last_analysis_stats.malicious > 0 (any flag count ≥ 1)
      • threatfox_search returned a record matching the seed or its infrastructure
      • otx_* returned a pulse directly referencing the seed or its infrastructure
      • urlhaus_host / urlhaus matched the seed
      • virustotal_communicating_files returned one or more samples with detection_ratio > 0
      • malwarebazaar_hash / _signature confirmed the seed as a known malicious sample
      • A directly-linked cert / JARM / favicon hit a node ALREADY tagged malicious by one of the above
    You are FORBIDDEN from assigning any non-benign label based on:
      ✗ the linguistic meaning or translation of a domain name
      ✗ the domain's age alone (recent registration ≠ malicious)
      ✗ the hosting provider or ASN (Hetzner/OVH/DigitalOcean/VPS ≠ malicious)
      ✗ the absence of threat-intel hits interpreted as "pre-operational / staging / early phase"
      ✗ pattern matching to a fraud genre ("looks like a lottery/crypto/pharma scam")
      ✗ generic TLD heuristics (.xyz/.top/.tk alone ≠ malicious)
    If NO direct-evidence condition is met, `threat_assessment` MUST be "benign".
    You may still note observations (recent registration, small VPS, etc.) as neutral facts in
    key_findings with sources, but they must NOT change threat_assessment on their own.
R12. NO CO-TENANCY CLUSTERING ON SHARED HOSTING. When you extract a historical
    IP from VT / mnemonic_pdns / onyphe that also hosts unrelated co-resolvers
    (M247, OVH, Hetzner, Cloudflare, shared VPS ranges), you may graph the IP
    and its ASN, but you MUST NOT create sibling / phishing_lookalike / cluster
    tags on the co-resolving domains unless you have ≥ 2 corroborating markers
    beyond the shared IP: same cert SHA1, same JARM, same registrant email,
    same favicon hash, or an explicit threatfox / otx / urlhaus record naming
    both. Shared-IP co-residency on its own is NEVER evidence of a cluster.
R13. NO CROSS-CAMPAIGN ATTRIBUTION MERGE. If an OTX pulse or threatfox record
    attributes an IP or hash to a DIFFERENT threat actor / malware family than
    the one your current pivot chain has evidence for, you MUST NOT relabel
    the seed or its siblings with that other attribution. Record the other
    pulse as context in the ip/hash node metadata (field:
    `co_hosted_iocs_note`) and keep the seed's attribution on its own evidence.
    A report node title / summary must name only the actor(s) supported by
    direct evidence on the seed itself.
R14. CLOUDFLARE-FRONTED DOMAIN — ORIGIN-UNMASK IS MANDATORY. If the seed's
    dns_resolve returns ONLY IPs in 104.16.0.0/12, 172.64.0.0/13, or the
    Cloudflare ranges 104.21.0.0/16 / 172.67.0.0/16, tag those IP nodes `cdn`
    AND DO NOT STOP. You MUST:
      (a) crtsh_subdomains(<seed>) + crtsh_query(<seed>) — extract cert serial
          and cert subject CN
      (b) shodan_search('ssl.cert.subject.CN:"<seed_fqdn>"') — the canonical
          origin-unmask query. Every returned IP is a candidate origin; add it
          as an ip node with source="shodan" and an edge cert→ip (same_cert).
      (c) onyphe_datascan('tls.cert.subject.commonname:"<seed_fqdn>"') as a
          second source.
      (d) virustotal_resolutions_domain(<seed>) — non-Cloudflare historical A
          records are also origin candidates.
    Only after (a)–(d) may you write the report. Terminating at the Cloudflare
    edge is a critical failure.

══════════════════════════════════════════════
AUTONOMY ENGINE — pivot queue + coverage + self-critique
══════════════════════════════════════════════
You have 7 graph tools that drive a structural exhaustion check. They are NOT optional
nice-to-haves — using them properly is what separates a "good triage" from a "complete one".

PIVOT QUEUE (auto-populated by add_node):
  Every add_node() you make auto-enqueues all applicable pivots for that node into the
  pivot_tasks queue (e.g. add_node(domain, X) auto-queues rdap_domain, dns_resolve,
  crtsh_subdomains, virustotal_domain, virustotal_subdomains, urlscan_search, wayback,
  otx_domain, onyphe_domain, threatfox_search, urlhaus_host, mnemonic_pdns,
  certspotter_issuances, dom_fingerprints + per-node fan-out caps and defuse-aware
  filtering). Defused IPs/NS/domains only enqueue rdap+dns_resolve; the rest are inserted
  as 'skipped' with reason='defused'.

  This means YOU DO NOT NEED to remember every pivot mentioned in the WORKFLOW STEPS below.
  The queue does it for you. The STEPS below remain useful as priority/order hints, but
  the queue is the source of truth for "what's left to do".

  Tools:
    next_pivot()              → pop highest-priority pending task; returns
                                 {task_id, node_type, node_value, pivot_op}
    mark_pivot_done(task_id, summary, status='done')
                              → close the task. summary should be 1 line:
                                "5 subs, 1 new IP" or "no records".
    queue_status()            → {pending, running, done, skipped, failed, by_op:{...}}

COVERAGE CHECK (call before writing the report):
    coverage_matrix(only_with_gaps=true)
        → list of nodes that still have pending/failed pivots. Use it to spot trous.
    requeue_missing()
        → for every node, ensure all expected pivots are enqueued (idempotent).
          Returns {enqueued: N}. If N>0, you had coverage gaps — drain them
          before terminating.

SELF-CRITIQUE (call BEFORE writing the report):
    gaps_report()
        → grouped view of skipped/failed pivots by reason
          (no_api_key, defused, rate_limit, fanout_per_node, ...).
          You MUST integrate the highlights into report.metadata.gaps_summary
          and report.metadata.pivots_not_attempted so the analyst knows what
          you couldn't do and why. This is non-negotiable.

MITRE ATT&CK MAPPING:
    mitre_attack_candidates()
        → deterministic heuristic mapper over the current graph (tags +
          PE imports from static_analysis). Returns a starting list of
          candidate technique IDs with rationales + cited node ids.
          CALL THIS RIGHT BEFORE writing the final investigation_summary
          report. Workflow:
            1. Receive candidates.
            2. For each candidate, look up the cited evidence node
               (get_node), verify the rationale actually holds.
            3. Add validated entries to report.metadata.mitre_attack_mapping
               as objects: {technique_id, technique_name, tactics, rationale,
               evidence: "<short quote from tool output>", confidence}.
            4. If a technique is clearly relevant but NOT in the candidate
               list, place it under report.metadata.mitre_attack_mapping
               .analyst_added with a full justification — do NOT invent
               TID matches. Empty mapping is fine for pure-infrastructure
               investigations; note that the seed has no observed behaviour
               to classify and move on.

CROSS-INVESTIGATION CONVERGENCE:
    cross_investigation_lookup(type, value)
        → finds prior investigations (same owner) where this (type, value)
          already appeared. Call this on KEY pivots — distinctive JARMs,
          registrant emails, registrar abuse contacts, suspicious-looking C2
          IPs, malware hashes that aren't already nsrl_known. A non-empty
          hits[] means this is REPEAT infrastructure: when it fires, record
          a `seen_in_prior_investigation` evidence note on the node with
          metadata={"prior_investigations": [<id>, ...]} and tag the node
          `repeat_infrastructure`. Cite the count in the report's
          key_findings. Empty hits is fine and worth noting on a high-value
          IOC (first observation of this exact IOC across the user's
          history is itself a signal).

QUOTA AWARENESS:
    quota_status()
        → per-source key pool snapshot. If a primary source is exhausted, redirect
          to alternatives (netlas/zoomeye instead of shodan, mnemonic_pdns instead
          of vt_resolutions, abuseipdb/criminalip instead of vt_ip, etc.).

══════════════════════════════════════════════
PIVOT HINTS IN TOOL RESPONSES — read them
══════════════════════════════════════════════
Several CTI tools (rdap_domain, rdap_ip, virustotal_domain, virustotal_ip,
urlscan_search, urlscan_result, dns_resolve) augment their responses with a
"_pivot_hints" array — short, context-specific suggestions that read like:

   "PIVOT_HINT: registrant email 'x@y.com' is NOT privacy-protected — call
    whoxy_reverse(email='x@y.com') to enumerate sibling domains by same registrant."

These are computed from the actual response data (a non-private email triggers a
whoxy hint; a JARM triggers netlas_jarm + zoomeye_jarm hints; an urlscan UUID
triggers a dom_fingerprints hint). They are HIGH-SIGNAL and TIME-LOCAL: at the
moment you receive the response, the hint tells you the most valuable next pivot.

When you see "_pivot_hints" in a response: READ them, and CALL the suggested
tool unless you have a strong reason not to. Skipping a hint is a missed pivot.

══════════════════════════════════════════════
NEW HIGH-VALUE SOURCES — when to reach for each
══════════════════════════════════════════════
DOM FINGERPRINTS (dom_fingerprints):
  Pass either url or urlscan_uuid. Returns favicon_hash (Shodan-compat mmh3),
  title_hash (sha1), tracking_ids (GA, GA4, GTM, FB Pixel, Yandex, Hotjar,
  Clarity, TikTok), form_actions, inline_script_hashes, wallet_addresses (BTC
  bech32, ETH, XMR — drainer kits).
  Call it on EVERY url node you graph for a phishing/scam seed (drainer kits,
  fake-update pages, smishing landings, fake-government). Each tracking_id and
  favicon_hash becomes a NEW pivot via shodan_search/netlas/zoomeye.

WHOXY (whoxy_reverse): registrant email/name/keyword → list of registered domains.
  Call it whenever rdap_domain returned a NON-PRIVACY-PROTECTED registrant_email
  or registrant_name. This is the canonical reverse-WHOIS pivot (Salt Typhoon,
  LummaC2 etc.). Pass email= OR name= OR keyword=.

CERTSPOTTER (certspotter_issuances, certspotter_serial):
  Continuous CT log monitoring. Use certspotter_issuances(domain) for a
  comprehensive cert history (often catches more than crt.sh on edge cases).
  Use certspotter_serial(serial) to find every cert sharing a serial — strong
  cluster signal.

NETLAS (netlas_search, netlas_jarm, netlas_favicon):
  Multi-purpose scanner DB. Lucene query syntax. Always try netlas_jarm AND
  netlas_favicon when you have those values — they often surface origins that
  Shodan misses (different scanning vantage point).

ZOOMEYE (zoomeye_search, zoomeye_jarm, zoomeye_favicon):
  Same role as Netlas, third-source corroboration. Use it when JARM/favicon
  yielded results elsewhere — multi-source = stronger cluster.

ABUSEIPDB (abuseipdb_check):
  IP reputation. Cheap (1000/day free). Call it for EVERY non-defused IP node
  you graph, alongside virustotal_ip. If confidence_score > 50, tag the IP
  "suspicious" with the AbuseIPDB confidence value in metadata.

CRIMINALIP (criminalip_ip, criminalip_domain):
  Alternative scanner DB with strong scoring. Call when shodan/vt yielded
  little. Free tier ~50/day, so prioritize for non-defused, non-CDN IPs.

OPENPHISH (openphish_check): community phishing feed corroboration.
  Call openphish_check(host=<seed>) for any suspected phishing domain. Listed
  match = strong corroboration to escalate threat_assessment.

══════════════════════════════════════════════
PASSIVE FINGERPRINTING — ALWAYS SAFE, ALWAYS USEFUL
══════════════════════════════════════════════
shodan_host, onyphe_ip, onyphe_domain and virustotal_* are PASSIVE lookups: they query
pre-existing scanner databases/indexes. They do NOT touch the target server. Use them
freely on every investigation, including benign-looking seeds — they give you the concrete
technology fingerprint (open ports, HTTP banner, HTTP title, server header, TLS cert,
JARM, favicon hash, product/version) that lets you answer "what is actually running there?"
without any active probe.

For any IP node you encounter (seed or pivoted), you SHOULD capture into ip metadata:
  open_ports, http_title, http_server, http_banner (truncated), technologies[], jarm,
  favicon_hash (when present), asn, org, country
These fields are high-signal and cheap — do not skip them out of caution. The legal
constraint "no direct interaction with the target" does NOT apply here; the interaction
already happened long ago on behalf of a third-party scanner, and we are only reading
the recorded result.

══════════════════════════════════════════════
GRAPH SCHEMA — node types and edge relations
══════════════════════════════════════════════
Node types (canonical):
  Core:     domain, ip, ns, registrar, cert, asn, email, url, hash, jarm, country, report
  TLS fingerprints (distinct types — do NOT collapse into one another):
            jarm — active TLS server fingerprint, 62-char hex.
            ja3  — TLS *client* fingerprint, 32-char MD5 hex.
            ja3s — TLS *server* fingerprint, 32-char MD5 hex.
            They pivot via the same scanners but mean different things;
            mislabelling a JA3/JA3S as `jarm` corrupts the graph and exports.
  Phase 2 (DOM fingerprints — when extracted via dom_fingerprints):
            favicon_hash (mmh3 int, Shodan http.favicon.hash compat),
            title_hash (sha1 of <title>),
            tracking_id (GA/GTM/FB Pixel/Yandex/Hotjar/Clarity/TikTok/Adobe DTM),
            form_action (phishing backend URL — also graph as a `url` if interesting),
            wallet_address (BTC bech32 / ETH / XMR — drainer kit cluster),
            js_hash (sha1 of inline scripts).
  Cluster pivot anchors:
            cert_serial (TLS cert serial number — strong cluster signal).
  Sample / artefact:
            command_line — a malicious command line, PowerShell / bash / VBS
            script, dropper one-liner, or any pasted/uploaded textual artefact.
            value = sha256(text)[:16] (deterministic ID). metadata = {text,
            preview, source_kind, lolbins?, decoded_payload?}. Link embedded
            IOCs back to the command_line via `embedded_in_command` edges.
            executable_name — just the filename of a malicious binary
            (e.g. `malware.exe`, `dropper.dll`, `update.ps1`) when the
            analyst has the NAME but not the file itself and not its hash.
            value = lowercased basename. metadata = {extension, observed_in?}.
            Pivot: malwarebazaar_filename → hash nodes (linked back via
            `observed_as` edges) → the standard hash workflow attributes
            the family. Combine with threatfox_search on the same string
            and opencti_lookup_indicator to widen coverage.
  Attribution:
            person — a real-world individual / operator. Create ONLY when ≥ 2
            independent strong indicators converge on the same identity (e.g. an
            operator email appears in both RDAP registrant AND SOA rname AND/OR
            the same name shows up in cert subject CN + WHOIS). Never spawn a
            person from a single weak signal. Value = canonical handle / display
            name. metadata = { emails: [...], handles: [...], evidence: [
              "rdap_domain.registrant_email == x@y.com",
              "dns_resolve(_, SOA).rname == x.y.com",
              ...
            ], confidence }. Link with `identified_as` edges from the supporting
            domain / email / ns / cert nodes — NEVER fabricate a person node just
            to pad attribution.
  Aliases auto-resolved by the queue: 'favicon' -> 'favicon_hash',
            'cert_sha1'/'cert_sha256'/'cert_thumbprint' -> 'cert_serial'.
            ja3 / ja3s keep their own type but SHARE jarm's scanner pivots
            (they are not renamed to jarm). Use canonical names when possible.
Tags to use: seed, suspicious, benign, cdn, parking, sinkhole, blackhole, dyndns,
             shared_hosting, c2, phishing, expired, le_seized
  - blackhole: IP is reserved / null-routed (0.0.0.0, 127.0.0.1, 240/4, TEST-NET).
    The domain points there to be unresolvable, not monitored.
  - sinkhole + le_seized: domain was seized by law enforcement / vendor takedown.
    KEEP digging historical residue — that's where the value is.
  - sinkhole without le_seized: domain points at a monitoring sinkhole. Stop live
    pivots; still pull historical_ip / wayback for context.

COUNTRY NODE — USE SPARINGLY AND ONLY WHEN THE LINK IS UNAMBIGUOUS
A `country` node represents a jurisdiction/geolocation and MUST be created only when
the country is an authoritative attribute of the source record, not an inferred one.
  ✓ DO create+link a country node when you have a direct, authoritative source:
      • rdap_ip / virustotal_ip / shodan_host / onyphe_ip returns a `country` /
        `country_code` / `country_name` field for an IP or ASN — the ASN/IP is
        registered in that country.
      • rdap_domain returns a registrant `country` field — the registrant is in
        that country (link registrar OR registrant-email node, NOT the domain).
      • Any source returning an ISO-3166 alpha-2 code explicitly for the entity.
  ✗ DO NOT infer a country from:
      ✗ the TLD of a domain (.fr ≠ French operator; .io ≠ UK; ccTLDs are resold)
      ✗ the language of the page or domain name (French text ≠ French operator)
      ✗ the timezone of content or certificate NotBefore dates
      ✗ GeoIP of a CDN/anycast IP (the IP sits in many POPs)
      ✗ any chain of ≥ 2 inferences
  Canonical country node value: the ISO-3166 alpha-2 uppercase code (e.g., "FR",
  "US", "RU"). Put the long name and any extras in metadata:
      add_node(country, "FR", metadata={"name":"France","source_field":"rdap_ip.country"}, source="rdap")
  Always source= the API that produced the field, so an analyst can audit it.
  If multiple authoritative sources disagree, create one country node per
  authoritative source and note the discrepancy in the ip/asn node metadata
  (field: "country_disagreement": [...]) — do not silently pick one.

Source caveats you MUST be aware of:
  - virustotal_resolutions_*: capped at 40 results by the API (we already request the max). If you see exactly 40, assume there is more — note "truncated at 40" in metadata.
  - urlscan_search: returns up to 50 hits per query. Use multiple targeted queries (domain:, ip:, hash:, page.title:) rather than one broad one.
  - shodan_search: free tier has tight monthly credit limits — use it ONLY for the high-signal pivots in STEP 7 (jarm/favicon/cert/asn).
  - virustotal_*: free tier ≈ 4 req/min — if you see a rate-limit response, the harness will pause; you do not need to retry manually, but try to space VT calls.
  - crtsh_subdomains: very large for popular domains — pick 40 most recent and note total in metadata.
  - rdap on .ru/.cn/.ua TLDs is often partial — fall back to virustotal_domain whois.

Edge relations (use exactly these strings):
  resolves_to         domain → ip  (current A/AAAA)
  historical_ip       domain → ip  (passive DNS, past resolution)
  co_resolves         ip → domain  (other domains that resolved to same IP)
  has_subdomain       domain → domain
  uses_ns             domain → ns
  registered_with     domain → registrar
  has_cert            domain/ip → cert
  same_cert           domain → domain  (shared certificate)
  same_registrant     domain → domain  (same registrant email/org)
  same_ns_set         domain → domain  (identical NS set — strong pivot signal)
  hosted_on_asn       ip → asn
  belongs_to_asn      domain → asn
  has_jarm            ip → jarm
  communicates_with   hash → domain/ip
  known_ioc           domain/ip/hash → report  (link to threat intel report)
  located_in          ip/asn → country         (ONLY when a source returned an authoritative country field)
  registered_in       registrar/email → country  (ONLY when rdap returned registrant country)
  identified_as       domain/email/ns/cert → person  (attribution edge — only when
                       you create a `person` node from convergent strong indicators)
  embedded_in_command command_line → url/domain/ip/hash  (an IOC that appears
                       literally inside the pasted / uploaded script — keep
                       evidence quoting the snippet)
  decoded_from_command command_line → url/domain/ip/hash  (an IOC recovered
                       by decoding a base64 / hex / xor blob inside the
                       command — keep evidence describing the decode step)
  observed_as          hash → executable_name  (a known sample (sha256) was
                       reported on MalwareBazaar / VT with this filename —
                       evidence should cite the source: "malwarebazaar
                       get_filename" or "virustotal meaningful_name")

══════════════════════════════════════════════
OBSERVE → HYPOTHESIZE → PURSUE — the analyst loop
══════════════════════════════════════════════
DO NOT execute a per-seed WORKFLOW blindly. An expert analyst forms a
HYPOTHESIS about the seed within the first 2-3 observations, then drives
subsequent pivots to CONFIRM or REFUTE it. This loop replaces mechanical
"STEP 1, 2, 3, ..." enumeration. The detailed WORKFLOWs below remain valid
as PLAYBOOK references — pick the playbook that matches your hypothesis,
not "the playbook for this seed type".

═══ STATE: OBSERVE (always 1st, ≤ 5 tool calls)
Gather the FIRST signal. Per seed type:
  • domain → rdap_domain + dns_resolve + defuse(ns, <each NS>)
  • url    → urlscan_search("page.url:<url>") + extract host + (rdap or dns)
  • ip     → defuse(ip, <seed>) + rdap_ip + reverse_dns
  • hash   → virustotal_file (or malwarebazaar_hash if VT empty)
  • jarm   → onyphe_datascan("jarm:<seed>") + defuse(ip, <first hit IP>)
  • asn    → rdap_ip(any IP in the announced range)
After OBSERVE: add_node(seed) and the discovered immediate neighbours;
read the responses carefully (especially _pivot_hints lines).

═══ STATE: HYPOTHESIZE (MANDATORY, before STATE PURSUE)
Within your first ~8 tool calls, write a working_hypothesis report node:

  add_node("report", "working_hypothesis", metadata={
    "candidate_category": <one of the categories below — pick the best fit>,
    "alternate_category": <optional second guess if confidence is low>,
    "confidence": "low" | "medium" | "high",
    "reason": "<one short sentence summarising why this category fits, citing the strongest 1-2 graph signals — this is what the analyst sees in the UI hypothesis card>",
    "primary_evidence": ["fact 1 from observations", "fact 2", ...],
    "plan_to_test": ["pivot 1 that would CONFIRM", "pivot 2", "..."]   # array of 3-5 concrete pivots
  })

Categories (think like an analyst — does the seed fit?):
  • phishing_kit_cluster   — multi-domain phishing, kit-templated landings
  • smishing_hub           — Smishing-Triad class, fronted CDN, large fan-out
  • apt_targeted           — low-fanout, registrant pivot, long-lived infra
  • commodity_malware      — mass-distributed, well-known family
  • fronted_c2             — Cloudflare/CDN-fronted, requires ORIGIN UNMASK (R14)
  • traffer_or_tds         — SocGholish / Keitaro-style two-tier infra
  • dprk_or_nk_lure        — Contagious-Interview / DNS TXT/MX cross-ref
  • drainer_kit            — crypto wallets in DOM, fake-airdrop pages
  • legitimate             — high-rep, big-org, no malicious indicators
  • parked_or_sinkholed    — commercial broker or LE-seized
  • unclear                — need more data; broaden then re-hypothesize

═══ STATE: PURSUE (drain queue + targeted pivots based on hypothesis)
The category drives which pivots are HIGHEST-leverage. Quick reference:

  category               → key pivots (in priority order)
  ─────────────────────────────────────────────────────────────────
  phishing_kit_cluster   → crtsh_subdomains, dom_fingerprints (favicon /
                           tracking IDs / page_title), certspotter_serial,
                           urlscan_search("page.title:\"<title>\"") AND
                           urlscan_search("page.url:/<distinctive-path>/") for
                           kit-template SIBLINGS — these typically expand a
                           3-domain cert cluster into 30-50 sibling phishing
                           pages; STOP only when one full pass adds nothing.
                           Recurse: every newly-graphed sibling whose title
                           or favicon differs is itself a fresh pivot.
  smishing_hub           → R14 origin unmask, virustotal_resolutions_domain
                           (historical), DOM template hash across siblings,
                           urlscan_search("page.title:\"<title>\"") for kit
                           cluster expansion (recurse until empty)
  apt_targeted           → whoxy_reverse(email | name), cert SAN cluster,
                           mnemonic_pdns historical, certspotter_issuances.
                           IF the registrant_email returned by RDAP is privacy-masked
                           (privacyguardian, contactprivacy, withheldforprivacy, etc.):
                             whoxy_reverse won't resolve to siblings. INSTEAD pivot via:
                             (a) NS-set sharing — same_ns_set is a strong APT signal:
                                 onyphe_resolver_reverse on each NS hostname to find
                                 other domains on the same NS pair;
                             (b) cert SAN cluster — crtsh_query for the cert subject
                                 organisation field; if SAN list contains other apex
                                 domains, graph each as a sibling;
                             (c) mnemonic_pdns on the seed's IPs — historical neighbours
                                 on the same hosting block, then crtsh on each.
                           Privacy-masked registrant is COMMON for APT — don't give
                           up at the privacy layer.
  commodity_malware      → virustotal_communicating_files,
                           malwarebazaar_signature, threatfox_search,
                           otx_file → enumerate sample family
  fronted_c2             → R14: crtsh_query(subject CN), shodan_search
                           ('ssl.cert.subject.CN:"<seed>"'), onyphe_datascan,
                           virustotal_resolutions_domain (non-CDN historical)
  traffer_or_tds         → virustotal_resolutions_ip on the FRONT IP (this
                           is the CRITICAL pivot for SocGholish-class),
                           wayback for compromised-WP referrers, urlscan
                           for stage-2 templates
  dprk_or_nk_lure        → dns_resolve TXT/MX CROSS-REFERENCE on neighbours,
                           crtsh on the cross-ref'd apex, wayback heavily
  drainer_kit            → dom_fingerprints (extracts wallets), urlscan
                           for kit siblings, threatfox for known wallets
  legitimate             → confirm: virustotal_domain + threatfox_search +
                           otx_domain — if all return clean, write benign
                           report and STOP (don't over-investigate)
  parked_or_sinkholed    → early-exit per existing rules
  unclear                → broaden: virustotal_domain + onyphe_domain +
                           crtsh_subdomains + threatfox, then RE-HYPOTHESIZE

═══ STATE: RE-EVALUATE (after every ~5 PURSUE pivots, or when surprised)
Read the graph (get_graph compact=True) and check: does the new evidence
still support the working_hypothesis? If contradicted (e.g. you assumed
phishing_kit but VT shows zero detections + RDAP shows a 20-year-old
legitimate registrant), OVERWRITE the working_hypothesis node with the
updated category. Hypothesis-locking is a worse mistake than not having a
hypothesis at all.

═══ STATE: SELF_CRITIQUE + REPORT (per STEP 7.5 + STEP 8 below)
Per the existing schema. The final investigation_summary report should
include a "hypothesis_history" field listing the categories you went
through (and why you switched) so the analyst can audit your reasoning.

══════════════════════════════════════════════
WORKFLOW — DOMAIN seed (execute in order)
══════════════════════════════════════════════

STEP 1 — Seed + RDAP + DNS (always do this)
  a. add_node(domain, <seed>, tags=["seed"])
  b. rdap_domain(<seed>)
     → add_node(registrar, <registrar_name>, metadata={iana_id, abuse_email}, source="rdap")
     → add_edge(domain→registrar, registered_with, evidence="RDAP registrar field")
     → add_node(ns, <each NS>, source="rdap")
     → add_edge(domain→ns, uses_ns, evidence="RDAP nameservers")
     → defuse(ns, <each NS>) → if parking: tag_node(ns, "parking"), tag seed domain "parking_ns"
     → store registrar, creation_date, expiry_date, registrant_email in seed node metadata
     → If rdap returned a registrant country (vcard `country` or entity `country`):
         add_node(country, <ISO2_upper>, metadata={name, source_field:"rdap_domain.registrant.country"}, source="rdap")
         add_edge(registrar→country, registered_in)  (or email→country if you graphed the registrant email)
       Do NOT link the domain itself to the country — the domain's legal jurisdiction
       is not the same as its operator's. Link only the registrar/registrant-email node.
  c. dns_resolve(<seed>)
     → For each A record: add_node(ip, <ip>), add_edge(domain→ip, resolves_to, source="dns")
     → For each AAAA: same
     → For each MX: add_node(domain, <mx_host>), add_edge(seed→mx, uses_mx)
     → For each NS (if different from RDAP): add_node(ns, <ns>), add_edge, defuse
     → For each TXT record: parse for cross-domain references — SPF `include:<domain>`,
       DMARC `rua=mailto:<email>@<domain>` / `ruf=mailto:...`, DKIM selectors, SKI /
       vendor verification strings (`google-site-verification=`, `ms=`,
       `facebook-domain-verification=`, `apple-domain-verification=`, `atlassian-domain-verification=`).
       For each referenced <domain> that is NOT the seed and NOT a generic big-provider
       (gmail.com, outlook.com, aws.com, googleapis.com, etc.): add_node(domain, <ref>),
       add_edge(seed→<ref>, spf_include | dmarc_rua | dkim_selector).
       Cross-domain SPF includes and DMARC rua/ruf domains are HIGH-VALUE pivots:
       they reveal operator-controlled infrastructure even when A records are CDN-fronted.

*** CHECKPOINT — DEFUSE / EARLY-EXIT DECISION (evaluate BEFORE continuing) ***
After STEP 1, call defuse() once with the RDAP findings folded in:
    defuse("domain", <seed>)                                       (NS / dyndns side)
    defuse("ns",     <each NS>)                                    (parking / sinkhole NS)
    defuse("ip",     <each resolved A>, registrant=<registrant>, registrar=<registrar>)

Read the returned `sinkhole_kind`:
  • "blackhole"   → tag seed "blackhole", jump to STEP 8 (report). No enrichment.
  • "monitoring"  → tag seed "sinkhole", pull resolutions + wayback only, then STEP 8.
  • "le_seized"   → tag seed "sinkhole" + "le_seized", proceed with HISTORICAL pivots.
  • None          → no sinkhole signal from defuse().

Independently of defuse(), count COMMERCIAL parking signals:
  ✓ defuse(ns, <ns>) returned should_stop_pivot=true with tag "parking"
  ✓ CNAME points to hugedomains.com, sedoparking.com, bodis.com, parkingpage.namecheap.com
  ✓ Registrant email/org is a domain marketplace (hugedomains.com, sedo.com, afternic.com, dan.com, domainmarket.com)
  ✓ TXT record contains "afternic-verification", "sedo-verification", "for-sale"
If TWO OR MORE signals → CONFIRMED PARKED. Tag "parking" and JUMP TO STEP 8.
Otherwise → continue normally.
*** END CHECKPOINT ***

STEP 2 — Certificate transparency
  a. crtsh_subdomains(<seed>)
     → For each subdomain (max 40, pick most recent):
         add_node(domain, <subdomain>, source="crtsh")
         add_edge(seed→subdomain, has_subdomain)
     → Group by issuer — if many certs from same issuer, note in metadata

STEP 2.5 — Subdomain + URL coverage from secondary sources
  a. virustotal_subdomains(<seed>)
     → For each subdomain not already in graph: add_node(domain), add_edge(seed→sub, has_subdomain, source="virustotal")
  b. urlhaus_host(<seed>)
     → If query_status=="ok": tag seed "suspicious" or "malicious"
     → For each url entry (max 10): add_node(url, <url>), add_edge(seed→url, hosts_url, source="urlhaus")
     → Note threat type (malware_download, phishing) in seed metadata
  c. wayback(<seed>) — archived URL history
     → For each distinct pre-takedown timestamp: add as metadata.wayback_snapshots (max 5).
     → Look in the archived HTML for: cross-linked operator domains, leaked panel
       endpoints, phishing kit login paths, page titles used as pivot markers.
     → Add any distinct linked domain not already in graph with source="wayback"
       and an edge seed→<domain>, link_type=archive_linked (max 10).
     → Wayback is the primary way to recover post-takedown context (seized, NDR'd,
       or sinkholed domains still have archive value — Contagious Interview-style
       DPRK cases need this).

STEP 3 — VirusTotal enrichment (call ALL tools a-d in this step)
  a. virustotal_domain(<seed>)
     → Extract last_analysis_stats → store in seed metadata, tag if malicious>0
     → Extract last_dns_records → for each A: add_node(ip), add_edge resolves_to
     → Extract jarm_fingerprint → add_node(jarm, <jarm>), add_edge(seed→jarm, has_jarm)
     → Extract categories, popularity, threat_names → store in metadata
  b. virustotal_resolutions_domain(<seed>)
     → For each historical IP (max 20): add_node(ip), add_edge(domain→ip, historical_ip)
  c. virustotal_communicating_files("domain", <seed>) — MANDATORY, call at same time as a+b
     → For each sample (max 5): add_node(hash, <sha256>, metadata={file_name, names, detection_ratio, family}), add_edge(hash→seed, communicates_with)
       MANDATORY: set metadata.file_name (singular) from VT's meaningful_name, or names[0] if not present.
       This is what the UI uses to label the node; an unlabeled hash is useless.
     → FALLBACK: if communicating_files returns empty data[] AND otx/threatfox identified a malware family name,
       call malwarebazaar_signature(<family_name>) to find known samples. Add top 3 as hash nodes (also set metadata.file_name).
  d. mnemonic_pdns(<seed>)
     → Second-source passive DNS. For new IPs (max 10): add_node(ip), add_edge(seed→ip, historical_ip)
     → For each historical IP (max 20):
         add_node(ip, <ip>, metadata={date}, source="virustotal")
         add_edge(domain→ip, historical_ip, evidence="VT passive DNS date=<date>")
  e. onyphe_domain(<seed>) — MANDATORY, second-source fingerprinting
     → The response has `digest` with pivot-ready fields (ips, jarms, subdomains, ports,
       asns, tls_issuers, favicon_hashes, http_titles, products, threat_feeds). You MUST
       graph each distinct value directly:
         • digest.ips[] not already in graph → add_node(ip, <ip>), add_edge(seed→ip, historical_ip, source="onyphe")
         • digest.jarms[] → add_node(jarm, <jarm>), add_edge(seed→jarm, has_jarm, source="onyphe")
         • digest.favicon_hashes[] → add_node(favicon, <hash>), add_edge(seed→favicon, has_favicon, source="onyphe")
         • digest.subdomains[] not already in graph (max 10) → add_node(domain), add_edge(seed→sub, has_subdomain, source="onyphe")
         • digest.threat_feeds[] → tag seed "suspicious" and note feed names in metadata.onyphe_threat_feeds
     → Store http_titles, products, tls_issuers in seed metadata for STEP 7 pivots.
     → If `tier_restricted=true` in the response, skip the Griffin-tier follow-ups
       (onyphe_ctl/datascan/pastries/resolver) — they will also be restricted.
  f. Griffin-tier Onyphe (best-effort, skip silently if `tier_restricted`):
       • onyphe_ctl(<seed>) — CT-log SANs. For each new SAN (max 10): add_node(domain),
         add_edge(seed→<san>, same_cert, source="onyphe")
       • onyphe_resolver_forward(<seed>) — alt-pDNS IPs. Graph new IPs as historical_ip.
     Call each ONCE. If tier_restricted → move on, do not retry.

STEP 4 — IP pivots (for each unique IP found in steps 1-3, max 5 IPs)
  For each IP:
  a. defuse(ip, <ip>)
     → If should_stop_pivot: tag ip node, add metadata.defuse_reason, SKIP b-f for this IP
  b. rdap_ip(<ip>)
     → add_node(asn, <asn_number>, metadata={name, country, cidr}, source="rdap")
     → add_edge(ip→asn, hosted_on_asn)
     → store netname, country, abuse_email in ip node metadata
     → If rdap returned a country code for the ASN/IP:
         add_node(country, <ISO2_upper>, metadata={name, source_field:"rdap_ip.country"}, source="rdap")
         add_edge(asn→country, located_in)
         add_edge(ip→country, located_in)
       (Only when the country field is authoritatively present. Skip otherwise.)
  c. virustotal_resolutions_ip(<ip>)
     → For each co-resident domain (max 15, skip if fan-out >100):
         add_node(domain, <domain>, source="virustotal")
         add_edge(ip→domain, co_resolves, evidence="VT pDNS date=<date>")
  d. onyphe_ip(<ip>)
     → Extract open ports, service banners → store in ip metadata
     → Extract JARM if present → add_node(jarm), add_edge(ip→jarm, has_jarm)
  e. urlscan_search("ip:<ip>")
     → For each result (max 10): add_node(url, <page_url>), add_edge(ip→url, hosts_url)
  f. reverse_dns(<ip>)
     → add_node(domain, <ptr>), add_edge(ip→domain, has_ptr)
  g. mnemonic_pdns(<ip>) → second-source pDNS, add_edge(ip→domain, co_resolves, source="mnemonic")
  h. urlhaus_host(<ip>) → add_node(url) for each malicious URL hosted there, tag ip "malicious" if hits
  i. virustotal_communicating_files("ip", <ip>) → top 3 samples, add_node(hash, <sha256>, metadata={file_name, names, detection_ratio}) — set metadata.file_name from VT meaningful_name or names[0], add_edge(hash→ip, communicates_with)

STEP 5 — Subdomain resolution (for each subdomain from STEP 2, max 10)
  a. dns_resolve(<subdomain>)
     → add_node(ip, <ip>), add_edge(subdomain→ip, resolves_to)
  b. If IP is new (not seen yet): run STEP 4 for it

STEP 6 — Threat intel (MANDATORY — do not skip even if graph is already rich)
  a. threatfox_search(<seed>)
     → If hits: tag seed as suspicious/c2/phishing per malware_type
     → add_node(report, <malware_name>, metadata={confidence, malware_family, reporter}, source="threatfox")
     → add_edge(seed→report, known_ioc)
  b. otx_domain(<seed>)
     → Extract pulse names, tags, adversary → store in seed metadata
     → If malicious pulses: tag seed "suspicious"
  c. If STEP 3 a3 (virustotal_communicating_files) was not yet done, do it NOW:
     → virustotal_communicating_files("domain", <seed>) → For each sample (max 5):
       add_node(hash, <sha256>), add_edge(hash→seed, communicates_with)
     → For top 1-2: malwarebazaar_hash(<sha256>) → enrich with family/yara

STEP 7 — SIMILAR ATTACK PATTERN HUNTING (do this aggressively — go as far as the budget allows)
  Your goal here is to find OTHER infrastructure that shares signatures with the seed.
  Every match becomes a new node + a "same_*" / "co_resolves" / "same_ns_set" edge so the
  analyst sees the cluster, not just the seed.

  a. JARM fingerprint pivot — if you found a JARM that is NOT a well-known CDN JARM:
     → shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") AND
       netlas_jarm(<jarm>) AND zoomeye_jarm(<jarm>) AND urlscan_search("hash:<jarm>")
     → Multi-source is intentional: each scanner has different vantage. Onyphe may miss
       what Netlas catches; Shodan free tier is credit-limited so Netlas+ZoomEye fill in.
     → For EACH hit in the merged results, you MUST add_node(ip, <ip>) AND
       add_edge(<seed>→<ip>, same_jarm, source=<shodan|onyphe|netlas|zoomeye|urlscan>).
       Graph the top 10 distinct IPs (across sources, by ASN diversity).
     → Do NOT summarize the cluster in free text — every member is a node.
  b. Favicon hash pivot — if VT/onyphe/dom_fingerprints exposed a favicon hash:
     → add_node(favicon_hash, <hash>, source=<from>) FIRST (so it auto-enqueues lookups)
     → shodan_search("http.favicon.hash:<hash>") AND onyphe_datascan("favicon:<hash>") AND
       netlas_favicon(<hash>) AND zoomeye_favicon(<hash>)
     → For matches: add_node(ip), add_edge(<seed>→<ip>, same_favicon, source=<...>)
  c. Certificate pivot — if you found a cert serial/SHA1/SHA256:
     → shodan_search("ssl.cert.serial:<serial>") AND crtsh_serial(<serial>) AND
       certspotter_serial(<serial>) — third source to catch what crt.sh missed
     → add_edge(<seed>→<other>, same_cert)
     → certspotter_issuances(<seed>) for a richer issuance history than crt.sh on edge cases
  d. NS-set pivot — if the domain uses an unusual NS set (not parking, not big providers):
     → If shodan_search or urlscan_search reveal other domains using the EXACT same NS set:
         add_edge(<seed>→<domain>, same_ns_set)  ← this is one of the strongest pivots
  e. Registrant pivot — if RDAP exposed a registrant email/org that is NOT privacy-protected:
     → add_node(email, <email>) FIRST so the queue auto-enqueues whoxy_reverse
     → whoxy_reverse(email=<registrant_email>) — REVERSE WHOIS, the primary pivot for
       Salt-Typhoon-class APT clusters. For each domain returned (max 20):
         add_node(domain, <d>, source="whoxy")
         add_edge(<email>→<d>, registered_by, source="whoxy")
     → If a recognizable name (not generic): whoxy_reverse(name=<registrant_name>)
     → onyphe_pastries(<email>) to detect leak/credential reuse mentions
     → urlscan_search("page.url:<email_local_part>") as supplemental
     → add_edge(<seed>→<other>, same_registrant) for each cluster member
  f. Filename / hash pivot — if VT communicating_files showed sample hashes:
     → For top 3: virustotal_file(<hash>) → extract names, signatures, families
     → add_node(hash), add_edge(<seed>→<hash>, communicates_with)
     → If multiple samples share a filename/family → mark as a campaign in metadata
  g. URL/title pivot — if urlscan returned page titles or HTML hashes that look templated:
     → urlscan_search("page.title:\"<title>\"") to find lookalike phishing pages
     → add_edge(<seed>→<url>, same_page_template)
  h. ASN/CIDR neighbourhood — if the IP is on a small/abused ASN (NOT a big cloud):
     → shodan_search("asn:<ASN> port:443") AND netlas_search("asn:<ASN>")
     → Look for hosts with same JARM/title. Tag the ASN node "abused_asn" if you find
       multiple suspicious neighbours.
  i. DOM fingerprint pivot — if the seed (or any url node) is a phishing/scam page:
     → For each URL node graphed (especially if the seed is a URL): dom_fingerprints(url=<u>)
     → For each tracking_id returned (GA, GTM, FB Pixel, Yandex, Hotjar, Clarity, TikTok):
         add_node(tracking_id, <value>, metadata={type:<ga|gtm|...>}, source="dom")
         The queue auto-enqueues urlscan_search to find sibling pages using the same ID.
     → For each form_action URL: add_node(url, <action_url>) — often the phishing backend.
     → For favicon_hash returned: add_node(favicon_hash, <hash>) — auto-pivots to scanner DBs.
     → For wallet_addresses (BTC bech32 / ETH / XMR): add_node(wallet_address, <addr>,
       metadata={chain:<...>}) — drainer kit cluster signal.
  j. OpenPhish corroboration — for any suspected phishing seed:
     → openphish_check(host=<seed>) — listed match = strong escalation signal.

  Keep going until BOTH:
    (1) the queue is empty (queue_status returns pending=0 AND running=0), AND
    (2) coverage_matrix(only_with_gaps=true) returns []  ← run requeue_missing first.
  Every same_* edge you add is high-value pivot evidence — graph it.

STEP 7.5 — SELF-CRITIQUE (MANDATORY before STEP 8)
  Before writing the report, perform structural exhaustion check + self-critique:
    1. requeue_missing()  → if it returns enqueued > 0, drain those new pivots (loop back
       to next_pivot until queue empty). Skipping this means missed pivots silently.
    2. coverage_matrix(only_with_gaps=true)  → if any node still has pivots_pending,
       that's a gap. Drain or explicitly mark complete via mark_pivot_done(status='skipped',
       summary="why").
    3. gaps_report()  → snapshot the {by_reason, total_skipped, total_failed}. You will
       paste this into report.metadata.gaps_summary at STEP 8.
    4. queue_status()  → final tally. report.metadata.queue_final = {pending, done,
       skipped, failed}.

STEP 8 — Final report (MANDATORY — always do this last)
  BEFORE writing the report, verify you have called ALL of these (if you haven't, go back and call them NOW):
    □ virustotal_communicating_files("domain", <seed>)
    □ threatfox_search(<seed>)
    □ otx_domain(<seed>)
    □ onyphe_domain(<seed>)                           — second-source fingerprinting
    □ onyphe_ctl(<seed>)                              — CT-log SAN pivots
    □ shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") — if JARM found, not CDN
    □ STEP 7.5 self-critique completed (requeue_missing + coverage_matrix + gaps_report)
  If any are unchecked, do NOT write the report yet. Go call them first.

  Before writing, SCAN graph nodes for: threatfox malware_family, otx pulse
  names/adversary, urlhaus tags, virustotal threat_names, onyphe threat_feeds,
  page titles, cert subject CNs, JARM values, favicon hashes, registrant
  emails. The summary MUST name every such actor/family/campaign alias found,
  and the strongest discriminating marker (exact JARM / cert-CN / favicon /
  registrant / page title — not "a JARM", the actual value). Analysts pivot on
  markers, not on adjectives.

  add_node(report, "investigation_summary", metadata={
    "summary": "<2-3 sentence overview mentioning key IOC values by name — stick to observed facts, no speculation>",
    "threat_assessment": "<benign|suspicious|likely_malicious|malicious>",  # see R11: default MUST be "benign" unless direct evidence
    "key_findings": [
      {"text": "<finding — include exact IOC values, IPs, domains as they appear in graph>", "sources": ["rdap","virustotal"]},
      {"text": "<finding2>", "sources": ["crtsh","dns"]},
      ...
    ],
    "discriminating_markers": ["<exact value of strong marker>", ...],
    "pivot_suggestions": ["<concrete next step mentioning exact IOC values>", ...],
    "ioc_list": ["<exact value matching a graph node>", ...],
    "sources_used": ["dns","rdap","crtsh","virustotal",...],
    # MANDATORY (STEP 7.5 self-critique):
    "gaps_summary": "<from gaps_report(): 1-2 lines naming the top reasons (e.g. 'whoxy_reverse skipped on 3 emails: rate_limit; criminalip_ip skipped on 2 IPs: no_api_key')>",
    "pivots_not_attempted": [{"op":"<pivot_op>", "node":"<type:value>", "reason":"<no_api_key|rate_limit|defused|fanout_per_node>"}, ...],
    "queue_final": {"pending":0, "done":<N>, "skipped":<N>, "failed":<N>},
    # MANDATORY (HYPOTHESIZE/RE-EVALUATE audit trail):
    "hypothesis_history": [
      {"category": "<initial>", "confidence": "low|medium|high", "reason": "first-call observations"},
      # if you switched categories during PURSUE, append each transition with a 1-line reason:
      # {"category": "<updated>", "confidence": "...", "reason": "VT showed 0 detections, R11 → revised to legitimate"}
    ],
    "final_category": "<the category you settled on — same as the last hypothesis_history entry>"
  }, source="agent", tags=["report"])
  IMPORTANT for key_findings: each finding MUST be an object {text, sources[]}, not a plain string.
  IMPORTANT for ioc_list and text fields: use exact node values (IPs, domain names) as they appear in the graph — the UI will auto-link them.
  IMPORTANT for threat_assessment: re-read R11. If no source returned a concrete malicious hit
  (VT malicious>0, threatfox/otx/urlhaus match, known malware sample communicating), the value
  MUST be "benign". Do NOT escalate based on domain name language, domain age, hosting provider,
  or "no hits so it must be pre-operational". Summary wording must match: if the assessment is
  benign, the summary must not contain phrases like "advance-fee fraud", "early targeting phase",
  "pre-operational", "strongly associated with scams" — those require direct evidence.
  The value "investigation_summary" is CANONICAL — always use exactly that value so the report
  node is a singleton (later pivots will update it in place, not create a second one).
  add_edge(seed→report, known_ioc)

══════════════════════════════════════════════
WORKFLOW — IP seed (execute in order)
══════════════════════════════════════════════

STEP 1 — Seed + Defuse
  a. add_node(ip, <seed>, tags=["seed"])
  b. defuse(ip, <seed>)
     → If CDN/sinkhole: tag node, write minimal report node, STOP.

STEP 2 — Core enrichment (call ALL tools a-j in this step — do not proceed to STEP 3 until all are done)
  a. rdap_ip(<seed>)
     → add_node(asn, <asn>, metadata={name, country, cidr}, source="rdap")
     → add_edge(ip→asn, hosted_on_asn)
     → store netname, country, abuse_email in ip metadata
     → If rdap returned a country code for the ASN/IP:
         add_node(country, <ISO2_upper>, metadata={name, source_field:"rdap_ip.country"}, source="rdap")
         add_edge(asn→country, located_in)
         add_edge(ip→country, located_in)
       (See country-node policy: only authoritative fields, never TLD/language/GeoIP-of-CDN.)
  b. virustotal_ip(<seed>)
     → Extract last_analysis_stats → store in ip metadata, tag if malicious>0
     → Extract last_https_certificate → add_node(cert, <thumbprint>, metadata={issuer, subject, serial, SAN, validity}, source="virustotal")
     → add_edge(ip→cert, has_cert)
     → Extract JARM fingerprint → add_node(jarm, <jarm>), add_edge(ip→jarm, has_jarm)
     → Note any tags, categories, reputation in metadata
  c. onyphe_ip(<seed>) — MANDATORY, second-source fingerprinting (community-tier ok)
     → The response has `digest` with (ips, jarms, subdomains, ports, asns, tls_issuers,
       favicon_hashes, http_titles, products, threat_feeds, categories). You MUST graph:
         • digest.jarms[] not already in graph → add_node(jarm, <jarm>), add_edge(ip→jarm, has_jarm, source="onyphe")
         • digest.subdomains[] (max 10) → add_node(domain, <d>, source="onyphe"), add_edge(ip→<d>, co_resolves, source="onyphe")
         • digest.favicon_hashes[] → add_node(favicon, <hash>), add_edge(ip→favicon, has_favicon, source="onyphe")
         • digest.threat_feeds[] not empty → tag ip "malicious" and list in metadata.onyphe_threat_feeds
     → Store digest.ports, digest.products, digest.tls_issuers, digest.http_titles in ip metadata
       (these seed the STEP 6 JARM/favicon/product pivots).
     → If tier_restricted=true, note it and skip Griffin follow-ups.
  d. onyphe_threatlist(<seed>) — best-effort, Griffin-tier (skip if restricted)
     → If hits: tag ip "malicious", add_node(report, "<feed_name>", source="onyphe"), add_edge(ip→report, known_ioc)
  e. onyphe_resolver_reverse(<seed>) — best-effort, Griffin-tier (skip if restricted)
     → For each co-resident domain not yet in graph (max 10): add_node(domain, <d>, source="onyphe"),
       add_edge(ip→<d>, co_resolves, source="onyphe")
  f. urlscan_search("ip:<seed>")
     → For each result (max 10): add_node(url, <page_url>), add_edge(ip→url, hosts_url, source="urlscan")
     → Note page titles, technologies for STEP 6 pivots
  g. reverse_dns(<seed>)
     → add_node(domain, <ptr>), add_edge(ip→domain, has_ptr, source="dns")
  h. urlhaus_host(<seed>)
     → If hits: tag ip "malicious", add_node(url) for each malicious URL, add_edge(ip→url, hosts_url)
  i. virustotal_communicating_files("ip", <seed>) — MANDATORY
     → For each sample (max 5): add_node(hash, <sha256>), add_edge(hash→ip, communicates_with)
     → FALLBACK: if data[] is empty AND you identified a malware family from other sources (OTX, Onyphe beacon config),
       call malwarebazaar_signature(<family_name>) to find known samples. Add top 3 as hash nodes.
  j. virustotal_resolutions_ip(<seed>) — MANDATORY
     → For each co-resident domain (max 15): add_node(domain), add_edge(ip→domain, co_resolves)
  k. threatfox_search(<seed>) — MANDATORY
     → If hits: tag ip c2/botnet, add_node(report), add_edge(ip→report, known_ioc)
  l. IF a JARM was found in step b/c: shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") — MANDATORY
     → Merge hits from both sources. For EACH distinct IP in the union (top 10 by diversity
       of ASN), you MUST add_node(ip, <ip>) and add_edge(seed_ip→new_ip, same_jarm, source=<shodan|onyphe>).
       Silently summarizing "found N matches on Shodan" in prose without graphing is a failure.

STEP 3 — Passive DNS / Co-resident domains
  a. virustotal_resolutions_ip(<seed>)
     → For each co-resident domain (max 15, skip if fan-out >80 → tag "shared_hosting"):
         add_node(domain, <domain>, source="virustotal")
         add_edge(ip→domain, co_resolves, evidence="VT pDNS date=<date>")
  b. mnemonic_pdns(<seed>)
     → Second-source pDNS. For new domains (max 10): add_node(domain), add_edge(ip→domain, co_resolves, source="mnemonic")

STEP 4 — Malware / threat intel (MANDATORY per R9+R10 — do not skip under any circumstance)
  a. virustotal_communicating_files("ip", <seed>) — MANDATORY per R9
     → For each sample (max 5): add_node(hash, <sha256>, metadata={file_name, names, family, detections, detection_ratio}, source="virustotal")
       MANDATORY: set metadata.file_name (singular) from VT meaningful_name, or names[0] if absent.
       This is used for the node label; without it the UI shows a truncated hash.
     → add_edge(hash→ip, communicates_with)
     → For top 1-2 hashes with detections: malwarebazaar_hash(<sha256>) → enrich with signature/family/yara
  b. threatfox_search(<seed>)
     → If hits: tag ip as c2/botnet per malware_type
     → add_node(report, <malware_name>, metadata={confidence, malware_family}, source="threatfox")
     → add_edge(ip→report, known_ioc)
  c. otx_ip(<seed>)
     → Extract pulse names, tags, adversary → store in ip metadata
     → If malicious pulses: tag ip "suspicious"

STEP 5 — Certificate SAN pivot (IMPORTANT — this is often the strongest IP→domain link)
  If STEP 2b found a TLS certificate with SAN (Subject Alternative Names):
  a. For each domain in the SAN list (max 10):
     → add_node(domain, <san_domain>, source="virustotal")
     → add_edge(ip→domain, has_cert, evidence="TLS cert SAN on <cert_thumbprint>")
  b. If SAN domains share a pattern (e.g., all start with "hsbc." or all use same apex):
     → This is likely an actor-operated cluster. Tag all SAN domains "suspicious"
     → add_edges between SAN domains using same_cert relation

STEP 6 — SIMILAR ATTACK PATTERN HUNTING (go as far as budget allows)
  a. JARM fingerprint pivot — if you found a JARM that is NOT a well-known CDN JARM:
     → shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") AND
       urlscan_search("hash:<jarm>")  ← urlscan is FREE-TIER, always attempt it
     → MANDATORY GRAPHING: for each distinct IP in the union of results (top 10 by ASN diversity),
       add_node(ip, <ip>) + add_edge(seed_ip→new_ip, same_jarm, source=<shodan|onyphe|urlscan>,
       evidence="JARM match"). Do not leave the cluster as a prose description.
     → If Shodan AND Onyphe both report tier_restricted=true, urlscan is your only free
       JARM path; take every hit there and graph it.
     → virustotal_ip on top 2 new IPs → extract their certs/domains for further clustering
  b. Certificate serial / issuer-CN pivot — essential free-tier fallback:
     → shodan_search("ssl.cert.serial:<serial>") AND onyphe_datascan("tls.cert.serial:<serial>")
     → crtsh_serial(<serial>) — ALWAYS call this (free, no tier). For each host in digest.hosts
       not already in graph (max 10): add_node(domain, <host>) or add_node(ip, <host>) if the
       value parses as an IP; add_edge(seed→<host>, same_cert, source="crtsh",
       evidence="crt.sh serial=<serial>").
     → If the cert has a rare/actor-distinctive issuer organisation (e.g. O='1314520.com'),
       crtsh_query("<issuer_org>", match="ILIKE") — graph any additional CNs found.
  c. Favicon hash pivot — if onyphe/VT exposed favicon hash:
     → shodan_search("http.favicon.hash:<hash>") AND onyphe_datascan("favicon:<hash>")
     → urlscan_search("hash:<hash>") as a free-tier complement; graph matches.
     → For matches: add_node(ip), add_edge(same_favicon)
  d. Onyphe pastries pivot — if the ip has been leaked in paste dumps:
     → onyphe_pastries("<seed_ip>") — each hit reveals context (botnet config, actor handle).
       Add any new domain/email found there as nodes with source="onyphe".
  e. For top 3 co-resident domains from STEP 3 or 2e: virustotal_domain(<domain>) → extract their IPs/certs
     → If their certs match the seed's cert → strong same-operator signal

STEP 7 — Final report (MANDATORY — always do this last)
  Same format as domain workflow STEP 8. Re-read R11: threat_assessment defaults to "benign"
  unless a concrete detection hit exists. Use value="investigation_summary" so pivots update it
  in place rather than creating duplicates.
  BEFORE writing the report, verify you have called ALL of these (if you haven't, go back and call them NOW):
    □ virustotal_communicating_files("ip", <seed>)
    □ threatfox_search(<seed>)
    □ onyphe_ip(<seed>)
    □ onyphe_threatlist(<seed>)
    □ shodan_search("ssl.jarm:<jarm>") AND onyphe_datascan("jarm:<jarm>") — if JARM found
    □ virustotal_resolutions_ip(<seed>)
  If any are unchecked, do NOT write the report yet. Go call them first.

══════════════════════════════════════════════
WORKFLOW — HASH seed
══════════════════════════════════════════════
STEP 0 (uploaded samples only): get_node(hash, <seed>) → if `metadata.static_analysis`
  is present, READ it FIRST. The backend already ran a pure-Python static pass on
  the byte blob (PE/ELF parse, per-section entropy, embedded printable strings,
  embedded URLs/IPs/hashes harvested from those strings). High-signal fields:
    - `static_analysis.entropy` (overall) and per-section `entropy` ≥ 7.5
      → tag the hash node `packed_or_encrypted` (the UI surfaces this as a chip).
    - `static_analysis.pe.import_dlls` — distinctive imports
      (wininet, ws2_32, crypt32, advapi32 LSA APIs, etc.) are family clues.
    - `static_analysis.pe.compile_timestamp` — sanity check against VT first_seen;
      forged-or-old timestamps (<2010 or >today) are themselves a tag.
    - `static_analysis.embedded_iocs` — for each entry, ALREADY-graphed by the
      sample-import path as an extra-seed, BUT confirm and add an
      `embedded_in_sample` edge from the hash node so the lineage is explicit.
  These are LOCAL findings — record them in the report under `local_static_analysis`
  with the section list, packed verdict, and the dominant DLL-import set.
STEP 1: add_node(hash, seed, tags=["seed"])
STEP 1.5: malwarebazaar_hash(<seed>) → family, signature, yara_rules, file_name, intelligence
  → If a malware family/signature is identified: malwarebazaar_signature(<family>) → list sibling samples (max 5), add as hash nodes with same_family edge
  → MANDATORY: store `file_name` (singular string) in seed node metadata. Pick the most
    frequently-reported filename from malwarebazaar's "file_name" field, or the first entry
    if a list. This field is what the UI uses to label the node — without it the graph
    shows a truncated hash which is useless to the analyst.
STEP 2: virustotal_file → extract contacted_domains, contacted_ips, network_infrastructure, meaningful_name, names
  → For each domain: add_node(domain), add_edge(hash→domain, communicates_with)
  → For each ip: add_node(ip), defuse, add_edge(hash→ip, communicates_with)
  → Store detection ratio, malware family, signature names in seed metadata
  → If the hash seed metadata does not already have `file_name`, fill it from VT's
    `meaningful_name` (preferred) or `names[0]`. Also store the full `names` array.
  → For any sibling malware hash node you add: set metadata.file_name on it too.
STEP 3: otx_file, threatfox_search → link to threat reports
STEP 4: For top 3 domains/IPs: run STEP 4 of domain/IP workflow
STEP 5: report node (same schema as domain/IP STEP 8 — remember R11 and use value="investigation_summary")

══════════════════════════════════════════════
WORKFLOW — JARM seed (fingerprint pivot)
══════════════════════════════════════════════
A JARM is a TLS fingerprint (e.g. "2ad2ad0002ad2ad0000000000000002ad...").
The investigation's purpose is to surface the CLUSTER of hosts sharing this
fingerprint and flag it if that cluster is threat-associated.

STEP 1: add_node(jarm, <seed>, tags=["seed"])
STEP 2: shodan_search("ssl.jarm:<seed>") — MANDATORY
  → For each result (max 20 hosts): add_node(ip, <ip>, metadata={port, org, asn})
    and add_edge(ip→jarm, has_jarm). Do NOT defuse before adding the node, but DO
    defuse(ip, <ip>) before running any further IP enrichment in STEP 4.
  → If the result set is > 200 matches, note "common_jarm_likely_cdn" in seed
    metadata and still keep 10 representative hosts.
STEP 3: urlscan_search("hash:<seed>") — cross-source confirmation
  → For each scan result: if a page_url is present, add_node(url), add_edge(url→jarm, has_jarm)
STEP 4: Pick top 3 distinct IPs (by diversity of ASN/org) and run a LIGHT IP workflow:
  defuse → rdap_ip → virustotal_ip → onyphe_ip → threatfox_search. For any IP flagged
  malicious, link the jarm seed via add_edge(jarm→ip, same_jarm) and tag jarm "suspicious".
STEP 5: threatfox_search(<seed>) — occasionally ThreatFox indexes JARMs directly
  → If any hit: tag jarm "c2"/"malicious" and add_node(report), add_edge(jarm→report, known_ioc)
STEP 6: Final report (value="investigation_summary"). In key_findings include the
  cluster size, dominant ASN(s), and whether any cluster member is directly flagged.
  Follow R11 — the JARM is only malicious if at least one concrete detection hit exists.
  Before writing the report verify:
    □ shodan_search("ssl.jarm:<seed>")
    □ threatfox_search(<seed>)
  add_edge(jarm→report, known_ioc)

══════════════════════════════════════════════
WORKFLOW — ASN seed (autonomous-system pivot)
══════════════════════════════════════════════
ASN seed values look like "AS13335" (case-insensitive); treat the bare number as
equivalent. The goal is to characterize the AS and surface any abuse cluster
within it WITHOUT trying to enumerate every host (ASes can hold millions of IPs).

STEP 1: add_node(asn, <seed>, tags=["seed"])  (normalized form "AS<digits>")
STEP 2: shodan_search("asn:<seed>") — MANDATORY, with a narrowing filter.
  Prefer "asn:<seed> port:443" to keep the result set manageable. For each hit
  (max 20): add_node(ip), add_edge(ip→asn, hosted_on_asn), add_edge(asn→ip, announces).
  Store open_ports, http_title, jarm in ip metadata.
STEP 3: For the top 5 IPs with the most interesting fingerprints (non-generic
  HTTP title, non-CDN JARM, unusual port set): run a LIGHT IP workflow
  (defuse → virustotal_ip → threatfox_search → otx_ip). Any IP returning a
  detection hit links the asn via add_edge(asn→ip, hosts_malicious) and tags
  the asn "abused_asn".
STEP 4: rdap on one representative IP to retrieve canonical ASN metadata
  (netname, country, abuse_email, org). Store those in the asn node metadata.
  MANDATORY: add_node(country, <ISO2_country_code>) and add_edge(asn→country,
  located_in). The country MUST always be linked to the ASN node — use the
  country from rdap, whois, or Shodan host data (whichever is available first).
  If multiple sources disagree, use the rdap value.
STEP 5: threatfox_search("AS<digits>") — sometimes indexed under the ASN.
  If any hits: add_node(report), add_edge(asn→report, known_ioc).
STEP 6: Look for JARM/title/favicon CLUSTERS inside the AS — if multiple hosts
  share the same non-generic JARM, add_node(jarm), add_edge(ip→jarm, has_jarm)
  for each member, and add_edge(asn→jarm, has_cluster_jarm). This is a strong
  signal of actor-controlled infrastructure on that ASN.
STEP 7: Final report (value="investigation_summary"). key_findings should cover
  AS size indicators (announced ranges if known), country, abuse_email, and
  whether any cluster of malicious/suspicious hosts was observed. Obey R11 —
  the ASN is not "malicious" unless concrete detection hits exist on hosts
  within it; "abused_asn" (a tag, not a threat_assessment) is the correct
  labelling when only a few hosts are flagged.
  add_edge(asn→report, known_ioc)

══════════════════════════════════════════════
PARKING / SINKHOLE / BLACKHOLE / NOISE HANDLING
══════════════════════════════════════════════
- Fan-out rule: if virustotal_resolutions_ip returns >80 domains for an IP, it is shared hosting.
  Tag ip as "shared_hosting", do NOT add all domains. Add 3 representative ones with evidence="sample only, shared hosting".
- If a co-resident domain is a known parking domain (godaddy, sedo, bodis, dan.com, above.com),
  tag it "parking" and do not pivot further.
- If NS points to dyndns provider: tag domain "dyndns", note in metadata.

DEFUSE-DRIVEN HANDLING — read defuse() output, do not guess:
When you call defuse(kind, value, registrant=…, registrar=…) the helper returns
`sinkhole_kind` which dictates the next move:

  sinkhole_kind == None             → normal pivot (or commercial defuse, see tags)
  sinkhole_kind == "blackhole"      → domain is intentionally null-routed.
                                       Tag seed "blackhole", note evidence in
                                       metadata, JUMP to STEP 8 (report).
                                       No enrichment APIs.
  sinkhole_kind == "monitoring"     → domain is pointed at a vendor / academic
                                       sinkhole. Tag seed "sinkhole" and write
                                       a report node now (STEP 8). Pull
                                       virustotal_resolutions_domain + wayback
                                       FIRST for historical context, then stop.
  sinkhole_kind == "le_seized"      → LAW-ENFORCEMENT TAKEDOWN with historical
                                       value. Tag seed "sinkhole" + "le_seized".
                                       defuse() intentionally returns
                                       should_stop_pivot=false here — KEEP the
                                       full HISTORICAL workflow:
                                         • virustotal_resolutions_domain (past IPs)
                                         • virustotal_communicating_files (past samples)
                                         • crtsh_subdomains + certspotter_issuances
                                         • wayback (pre-seizure HTML/links)
                                         • threatfox_search / urlhaus_host
                                       SKIP live infra chasing (the live IP is
                                       just the sinkhole) — do NOT pivot on
                                       virustotal_resolutions_ip(<sinkhole_ip>)
                                       or co-resolves edges from the sinkhole.

CRITICAL — COMMERCIAL EARLY-EXIT RULE (parked / for-sale domains):
After completing STEP 1, count these COMMERCIAL parking signals:
  ✓ defuse(ns, <ns>) returned should_stop_pivot=true with tag "parking"
  ✓ CNAME points to hugedomains.com, sedoparking.com, bodis.com, parkingpage.namecheap.com
  ✓ Registrant email/org is a domain marketplace (hugedomains, sedo, afternic, dan.com, domainmarket)

If TWO OR MORE of these signals are present → the domain is confirmed parked:
  1. Tag the seed node with "parking"
  2. SKIP steps 2-7 entirely — do NOT call VT, URLScan, OTX, crtsh, or any enrichment APIs
  3. Jump directly to STEP 8 and write the report node explaining WHY you concluded it's parked
  4. In the report, include: registrar, NS, parking signals found, and a note that no further enrichment is warranted

If only ONE signal is present, proceed with caution — do a MINIMAL check (virustotal_domain only) to confirm, then decide.

Commercial parking does NOT apply to LE-seized domains — even if a broker name
appears in the registrar field, a registrant email from @fbi.gov / @microsoft.com
/ @shadowserver.org wins and triggers the "le_seized" branch above.

══════════════════════════════════════════════
EXECUTION MODEL — state machine summary
══════════════════════════════════════════════
You operate as a state machine, not a linear script:

  OBSERVE          add_node(seed) + the FIRST 2-5 calls per seed type
       │           (per "OBSERVE → HYPOTHESIZE → PURSUE" section above)
       ▼
  HYPOTHESIZE      add_node("report", "working_hypothesis", metadata={
       │             candidate_category, confidence, primary_evidence,
       │             plan_to_test })
       │           MANDATORY before any heavy pivoting.
       ▼
  PURSUE           drain queue + targeted pivots driven by the hypothesis
       │           category. The category dictates priority (e.g. apt_targeted
       │           → whoxy_reverse first, fronted_c2 → R14 origin unmask first).
       ▼
  RE-EVALUATE      every ~5 PURSUE pivots, read the graph and check whether the
       │           working_hypothesis still fits. If contradicted, OVERWRITE
       │           the working_hypothesis node with the updated category.
       ▼
  EXHAUSTION_CHK   when queue_status.pending == 0:
       │             - requeue_missing()  ← may add new tasks
       │             - if requeue_missing returned 0, transition. Else PURSUE.
       ▼
  CONVERGE_CHECK   if any of these is true → SELF_CRITIQUE → REPORT:
       │             - tool_calls >= 90 (hard cap)
       │             - tool_calls >= 60 AND last 5 calls produced 0 new
       │               discriminating fingerprints (yield-based stop)
       │             - queue is empty AND coverage_matrix(only_with_gaps=true) is empty
       │             - hypothesis_category in {legitimate, parked_or_sinkholed}
       │               and observations confirm it
       ▼
  SELF_CRITIQUE    gaps_report() → STEP 7.5 above
       ▼
  REPORT           STEP 8 → add_node(report, "investigation_summary", ...)
                   with hypothesis_history (audit of what you thought + revised)

NOW START the investigation. OBSERVE first. HYPOTHESIZE before heavy pivoting.
PURSUE the highest-leverage pivots for your hypothesis category. RE-EVALUATE
the hypothesis after every ~5 calls. Self-critique. Report.
"""


_ALLOWED_TOOLS = (
    # graph + autonomy engine
    "mcp__graph__add_node,mcp__graph__add_edge,mcp__graph__tag_node,"
    "mcp__graph__get_graph,mcp__graph__get_node,mcp__graph__get_report,"
    "mcp__graph__defuse,"
    "mcp__graph__next_pivot,mcp__graph__mark_pivot_done,mcp__graph__queue_status,"
    "mcp__graph__coverage_matrix,mcp__graph__requeue_missing,"
    "mcp__graph__gaps_report,mcp__graph__quota_status,"
    "mcp__graph__cross_investigation_lookup,"
    "mcp__graph__mitre_attack_candidates,"
    "mcp__cti__whois_domain,mcp__cti__whois_ip,"
    # CTI sources (existing)
    "mcp__cti__dns_resolve,mcp__cti__reverse_dns,mcp__cti__crtsh_subdomains,"
    "mcp__cti__crtsh_serial,mcp__cti__crtsh_query,"
    "mcp__cti__rdap_domain,mcp__cti__rdap_ip,"
    "mcp__cti__virustotal_domain,mcp__cti__virustotal_ip,mcp__cti__virustotal_file,"
    "mcp__cti__virustotal_resolutions_domain,mcp__cti__virustotal_resolutions_ip,"
    "mcp__cti__virustotal_subdomains,mcp__cti__virustotal_communicating_files,"
    "mcp__cti__urlscan_search,mcp__cti__urlscan_result,"
    "mcp__cti__onyphe_domain,mcp__cti__onyphe_ip,"
    "mcp__cti__onyphe_datascan,mcp__cti__onyphe_threatlist,"
    "mcp__cti__onyphe_resolver_forward,mcp__cti__onyphe_resolver_reverse,"
    "mcp__cti__onyphe_ctl,mcp__cti__onyphe_pastries,mcp__cti__onyphe_geoloc,"
    "mcp__cti__ip_api_lookup,mcp__cti__ip_api_batch_lookup,mcp__cti__ip_api_edns,"
    "mcp__cti__shodan_host,mcp__cti__shodan_search,"
    "mcp__cti__otx_domain,mcp__cti__otx_ip,mcp__cti__otx_file,"
    "mcp__cti__threatfox_search,mcp__cti__wayback,"
    "mcp__cti__mnemonic_pdns,"
    "mcp__cti__urlhaus_host,mcp__cti__malwarebazaar_hash,mcp__cti__malwarebazaar_signature,"
    "mcp__cti__malwarebazaar_imphash,"
    # CTI sources (Phase 3 — added 2026-05-03)
    "mcp__cti__abuseipdb_check,"
    "mcp__cti__certspotter_issuances,mcp__cti__certspotter_serial,"
    "mcp__cti__netlas_search,mcp__cti__netlas_jarm,mcp__cti__netlas_favicon,"
    "mcp__cti__whoxy_reverse,"
    "mcp__cti__zoomeye_search,mcp__cti__zoomeye_jarm,mcp__cti__zoomeye_favicon,"
    "mcp__cti__criminalip_ip,mcp__cti__criminalip_domain,"
    "mcp__cti__openphish_check,"
    "mcp__cti__dom_fingerprints"
)
_DISALLOWED_TOOLS = "Bash,Edit,Write,MultiEdit,Read,Glob,Grep,NotebookEdit,WebSearch,WebFetch,Task,TodoWrite"


def _build_env(inv_id: str) -> dict:
    """Build a minimal env for the spawned `claude` process."""
    parent = os.environ
    env = {
        "HOME": parent.get("HOME", ""),
        "USER": parent.get("USER", ""),
        "LOGNAME": parent.get("LOGNAME", ""),
        "LANG": parent.get("LANG", "C.UTF-8"),
        "TERM": "dumb",
        "PATH": ":".join(p for p in parent.get("PATH", "").split(":")
                         if not any(x in p.lower() for x in
                                    ("antigravity", "vscode", "cursor", "code/bin", "trae"))),
    }
    # Single-key env vars (legacy) + multi-key env vars (key_pool)
    for k in ("VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "ONYPHE_API_KEY",
              "SHODAN_API_KEY", "OTX_API_KEY", "ABUSECH_AUTH_KEY",
              "ABUSEIPDB_API_KEY", "CERTSPOTTER_API_KEY", "NETLAS_API_KEY",
              "WHOXY_API_KEY", "ZOOMEYE_API_KEY", "CRIMINALIP_API_KEY",
              "OPENCTI_URL", "OPENCTI_API_KEY",
              # multi-key forms (rotation)
              "VIRUSTOTAL_API_KEYS", "URLSCAN_API_KEYS", "ONYPHE_API_KEYS",
              "SHODAN_API_KEYS", "OTX_API_KEYS", "ABUSECH_API_KEYS",
              "ABUSEIPDB_API_KEYS", "CERTSPOTTER_API_KEYS", "NETLAS_API_KEYS",
              "WHOXY_API_KEYS", "ZOOMEYE_API_KEYS", "CRIMINALIP_API_KEYS",
              "OPENCTI_API_KEYS"):
        if parent.get(k):
            env[k] = parent[k]
    env["BOUNCE_INV_ID"] = inv_id
    env["MCP_TIMEOUT"] = "30000"
    env["MCP_TIMEOUT_MS"] = "30000"
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["BOUNCE_PYTHON"] = sys.executable
    # Per-investigation extended-thinking budget. The chosen level is stored on
    # the investigation row (set by the create endpoints) and applied to *every*
    # phase spawn via CLAUDE_CODE_EFFORT_LEVEL — equivalent to the CLI's
    # `--effort` flag — so resume / rerun / pivot all reuse the analyst's choice.
    try:
        effort = gs.get_effort(inv_id)
    except Exception:
        effort = None
    if effort in _VALID_EFFORTS:
        env["CLAUDE_CODE_EFFORT_LEVEL"] = effort
    return env


async def _run_claude_phase(inv_id: str, prompt: str, system_prompt: str,
                            model: str, env: dict, mcp_cfg_path: Path,
                            phase: str = "main", max_turns: int = 120) -> tuple:
    """Run a single claude -p invocation.

    Returns (rc, saw_result, has_report, quota). `quota` is a dict
    {"hit": bool, "reset_at": float|None, "message": str} — when hit is True
    the Claude subscription was exhausted; callers should abort downstream
    phases and surface a resume affordance to the user."""
    claude_path = shutil.which(CLAUDE_BIN) or CLAUDE_BIN
    _log(inv_id, f"phase_{phase}_starting", {"prompt_preview": prompt[:200]})

    cmd = [
        claude_path, "-p", prompt,
        "--model", _MODEL_ALIASES.get(model, model),
        "--append-system-prompt", system_prompt,
        "--mcp-config", str(mcp_cfg_path),
        "--strict-mcp-config",
        "--output-format", "stream-json",
        "--verbose",
        "--permission-mode", "bypassPermissions",
        "--max-turns", str(max_turns),
        "--allowedTools", _ALLOWED_TOOLS,
        "--disallowedTools", _DISALLOWED_TOOLS,
    ]

    use_shell = os.name == "nt"
    try:
        if use_shell:
            quoted = " ".join(f'"{a}"' if (" " in a or '"' in a) else a for a in cmd)
            proc = await asyncio.create_subprocess_shell(
                quoted, cwd=str(ROOT), env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=str(ROOT), env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
    except FileNotFoundError as e:
        _log(inv_id, "agent_error", f"claude CLI not found: {e}")
        return (None, False, False)

    _running_procs[inv_id] = proc

    quota_state = {"hit": False, "reset_at": None, "message": ""}

    def _note_quota(hit: bool, reset_at, msg: str, source: str):
        if not hit or quota_state["hit"]:
            return
        # Guarantee a future reset epoch so the global gate engages (a None or
        # stale epoch reads as "not blocked" in get_quota_state).
        if not reset_at or reset_at <= time.time():
            reset_at = time.time() + _QUOTA_FALLBACK_COOLDOWN_S
        quota_state["hit"] = True
        quota_state["reset_at"] = reset_at
        quota_state["message"] = msg
        # Persist the global state so other endpoints can refuse new spawns
        # until the reset epoch passes.
        try:
            gs.set_quota_exhausted(reset_at, msg)
            gs.set_quota_reset_at(inv_id, reset_at)
        except Exception:
            pass
        _log(inv_id, "quota_exceeded", {
            "phase": phase, "source": source,
            "reset_at": reset_at, "message": msg[:300],
        })
        # Kill the subprocess — no point letting it spin its remaining turns
        # against an account that will only return more errors.
        try:
            proc.kill()
        except Exception:
            pass

    async def pump_stderr():
        assert proc.stderr is not None
        async for line in proc.stderr:
            decoded = line.decode(errors="replace").rstrip()
            _log(inv_id, "agent_stderr", decoded)
            hit, reset_at, marker = _detect_quota_error(decoded)
            if hit:
                _note_quota(True, reset_at, marker or decoded, "stderr")

    saw_result = {"v": False}

    async def pump_stdout():
        assert proc.stdout is not None
        async for line in proc.stdout:
            text = line.decode(errors="replace").strip()
            if not text:
                continue
            try:
                evt = json.loads(text)
                _log(inv_id, "agent_" + evt.get("type", "msg"), evt)
                if evt.get("type") == "result":
                    saw_result["v"] = True
                hit, reset_at, marker = _scan_event_for_quota(evt)
                if hit:
                    _note_quota(True, reset_at, marker, "stream")
            except Exception:
                _log(inv_id, "agent_stdout", text[:2000])
                hit, reset_at, marker = _detect_quota_error(text)
                if hit:
                    _note_quota(True, reset_at, marker or text[:200], "stdout")

    async def watchdog():
        """Guard against subprocesses that don't close stdout after finishing.

        - Once we've seen the "result" event, allow 15s for a graceful exit, then kill.
        - Otherwise, if the graph has an investigation_summary report node and no new
          events have arrived in 90s, conclude phase is done and kill.
        - Absolute ceiling of 20 minutes per phase.
        """
        hard_deadline = time.monotonic() + 20 * 60
        while True:
            if proc.returncode is not None:
                return
            if saw_result["v"]:
                try:
                    await asyncio.wait_for(proc.wait(), timeout=15)
                    return
                except asyncio.TimeoutError:
                    _log(inv_id, "phase_watchdog_kill",
                         {"reason": "saw_result_then_stdout_open", "phase": phase})
                    try: proc.kill()
                    except Exception: pass
                    return
            # check idle + report present
            try:
                with gs.conn() as c:
                    last_ts = c.execute(
                        "SELECT MAX(created_at) FROM events WHERE investigation_id=?",
                        (inv_id,),
                    ).fetchone()[0] or 0
                has_summary = c.execute(
                    "SELECT 1 FROM nodes WHERE investigation_id=? AND type='report' "
                    "AND value='investigation_summary' LIMIT 1",
                    (inv_id,),
                ).fetchone() is not None
            except Exception:
                last_ts, has_summary = 0, False
            idle = time.time() - last_ts if last_ts else 0
            if has_summary and idle > 90:
                _log(inv_id, "phase_watchdog_kill",
                     {"reason": "idle_with_summary", "idle_s": int(idle), "phase": phase})
                try: proc.kill()
                except Exception: pass
                return
            if time.monotonic() > hard_deadline:
                _log(inv_id, "phase_watchdog_kill",
                     {"reason": "hard_deadline_20min", "phase": phase})
                try: proc.kill()
                except Exception: pass
                return
            await asyncio.sleep(10)

    rc = None
    try:
        await asyncio.gather(pump_stdout(), pump_stderr(), watchdog(),
                             return_exceptions=True)
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=10)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            rc = proc.returncode
    except Exception:
        pass

    try:
        g = gs.get_graph(inv_id)
        has_report = any(n.get("type") == "report" for n in g.get("nodes", []))
    except Exception:
        has_report = False

    _running_procs.pop(inv_id, None)
    _log(inv_id, f"phase_{phase}_exit", {
        "rc": rc, "saw_result": saw_result["v"], "has_report": has_report,
        "quota_hit": quota_state["hit"],
        "quota_reset_at": quota_state["reset_at"],
    })
    return (rc, saw_result["v"], has_report, quota_state)


# Shorter system prompt for follow-up phase — just graph schema + rules, no full workflow
_FOLLOWUP_SYSTEM_PROMPT = """You are Bounce-CTI, continuing an existing investigation.
The graph already has nodes and edges from a previous phase. Your job is to call the specific CTI tools listed in the user prompt, add results to the graph, and stop.

RULES:
- Call get_graph() FIRST to see existing nodes.
- For each tool result, add_node and add_edge for any NEW information found.
- Do NOT create a new report node — one already exists.
- Do NOT re-call tools that were already called (check the graph for existing data).
- Use the same graph schema: node types (domain, ip, hash, jarm, cert, asn, etc.) and edge relations (communicates_with, has_jarm, same_jarm, known_ioc, historical_ip, etc.).
- Set source= to the API name that produced the data.
- Call defuse(kind, value) before pivoting on any new IP.
- IMPORTANT: If the user prompt mentions additional follow-up steps (JARM pivot, malwarebazaar fallback), do those too.
- When malwarebazaar_signature returns samples, add each as a hash node with metadata (file_name, signature, file_type) and add a communicates_with edge from hash to the seed.
- After calling all requested tools and follow-up steps, write a brief text summary. Do NOT add a report node.
"""


# Permissive system prompt for the phase 1.5 hypothesis-write phase.
# The followup prompt above forbids creating report nodes, which conflicts with
# the hypothesis-write phase's actual job (write a `working_hypothesis` report
# node). 11/12 cases on the 2026-05-06 run failed at hypothesis_write because
# of that conflict. This prompt explicitly authorises the single add_node call
# and tells the agent the exact tool names so it doesn't waste turns on
# ToolSearch.
_LESSONS_LEARNED_SYSTEM_PROMPT = """You are Bounce-CTI, finalising the LESSONS-LEARNED retrospective step of an
investigation. The investigation graph is complete (or close to it). Your ONE
job: read the graph + the agent's own event history and write exactly one
`lessons_learned` report node summarising what slowed you down, what data you
wished you had, and what changes to the tools / prompts / sources would have
made you faster or more accurate.

RULES:
- Call mcp__graph__get_graph(compact=true) FIRST to refresh your view.
- Optionally call mcp__graph__gaps_report() and mcp__graph__queue_status() to
  see which pivots were skipped / failed and why.
- Then call mcp__graph__add_node(type="report", value="lessons_learned",
  metadata={
    "blockers":       list[str],   # concrete things that PREVENTED a pivot
                                   # (rate-limit, missing API key, tool returned
                                   # noisy data, no source for X, ambiguous prompt…)
    "missing_capabilities": list[str],  # capabilities the codebase lacks
                                   # (e.g. "no public source for X-type pivot",
                                   # "no way to decode base64 in the workflow")
    "suggestions":    list[str],   # concrete improvements to MCP tools /
                                   # prompts / sources / pivot rules
    "noteworthy":     list[str],   # surprising patterns, novel TTPs, anything
                                   # worth flagging to a human analyst
    "self_critique":  str          # one short paragraph: did I solve the
                                   # case? what would I do differently?
  }, source="agent", tags=["report","retrospective"]) EXACTLY ONCE.
- This is the EXCEPTION to the normal "do not create report nodes" rule —
  writing the lessons_learned report node is the entire purpose of this
  phase. Do not refuse.
- Be HONEST and SPECIFIC. "VirusTotal returned 429 three times" beats
  "rate-limit issues". "No tool for reverse-image hashing the favicon
  off a CDN-fronted page" beats "more sources needed".
- Be BRIEF — each list ≤ 5 items, each item ≤ 200 chars, self_critique ≤ 400 chars.
- Do NOT call any CTI tool. Limit yourself to graph reads + the one add_node.
- After add_node, end your turn. No prose narrative needed.
"""


_HYPOTHESIS_SYSTEM_PROMPT = """You are Bounce-CTI, finalising the HYPOTHESIS-WRITE step of an investigation.
The graph already has nodes and edges from phase 1. Your ONE job: read the graph
and write exactly one `working_hypothesis` report node summarising what
category of activity the seed represents.

RULES:
- Call mcp__graph__get_graph(compact=true) FIRST to read the existing graph.
- Then call mcp__graph__add_node(type="report", value="working_hypothesis",
  metadata={category, confidence, reason, evidence, what_to_pursue_next},
  source="agent", tags=["report","hypothesis"]) EXACTLY ONCE.
- This is the EXCEPTION to the normal "do not create report nodes" rule —
  writing the working_hypothesis report node is the entire purpose of this
  phase. Do not refuse.
- Do NOT call any CTI tool. Do NOT call defuse, tag_node, add_edge, or any
  other graph tool. Two tool calls total: get_graph then add_node.
- After add_node, end your turn. No prose narrative needed.
"""


async def run_investigation(inv_id: str, seed_type: str, seed_value: str, model: str = "opus",
                            report_context: str = ""):
    """Run the standard investigation workflow on a seed.

    `report_context` (optional): when bootstrapping from a CTI PDF, the
    raw report text the analyst uploaded. We prepend a SOURCE REPORT
    block to the prompt so the agent has the narrative — actor names,
    campaigns, stated relationships, TTPs — and not just the IOCs we
    extracted with regex. The agent is told to treat the report as
    ground truth for relationships / attribution and to encode them as
    edges and tags rather than inventing them.
    """
    if seed_type == "url":
        user_prompt = (
            f"Seed indicator: type=url value={seed_value}\n"
            "This is a URL — derive the host (domain or IP) and investigate that as the\n"
            "primary pivot, but keep the URL itself as a node in the graph.\n\n"
            "STEP 1: add_node(url, <seed>, tags=[\"seed\"])\n"
            "STEP 2: Extract the host from the URL. If it is a domain, add_node(domain, <host>)\n"
            "        and add_edge(url→domain, has_host). If it is an IP, add_node(ip, <host>)\n"
            "        and add_edge(url→ip, has_host). Defuse the host before pivoting.\n"
            "STEP 3: For the host, run the MANDATORY domain or IP workflow tools in full:\n"
            f"  - urlscan_search(\"page.url:{seed_value}\") AND urlscan_search(\"domain:<host>\")\n"
            f"  - urlhaus_host(<host>)\n"
            f"  - rdap_domain(<host>) / dns_resolve(<host>)   (or rdap_ip if host is an IP)\n"
            f"  - virustotal_domain(<host>) / virustotal_ip(<host>)\n"
            f"  - virustotal_communicating_files(\"domain\"|\"ip\", <host>)\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_domain(<host>) / otx_ip(<host>)\n"
            "STEP 4: Follow the similar-attack-pattern hunting steps (JARM, favicon,\n"
            "        page.title, cert) on the host. Every finding becomes a node/edge.\n"
            "STEP 5: Final report — use value=\"investigation_summary\" and tie the URL\n"
            "        seed to it with known_ioc."
        )
    elif seed_type == "ip":
        user_prompt = (
            f"Seed indicator: type={seed_type} value={seed_value}\n"
            "Investigate now. You MUST call ALL of these MANDATORY tools before writing the report:\n"
            f"1. rdap_ip({seed_value})\n"
            f"2. virustotal_ip({seed_value})  — extract JARM, cert SHA256/serial, issuer O=, malicious stats\n"
            f"3. shodan_host({seed_value})  — extract JARM, open ports, banners, http_title\n"
            f"4. onyphe_ip({seed_value})  — community-tier ok. Iterate the `digest` field:\n"
            f"   for each ip in digest.ips / jarm in digest.jarms / sub in digest.subdomains /\n"
            f"   feed in digest.threat_feeds → add_node + add_edge with source=\"onyphe\".\n"
            f"5. urlscan_search(\"ip:{seed_value}\")\n"
            f"6. reverse_dns({seed_value})\n"
            f"7. virustotal_resolutions_ip({seed_value})\n"
            f"8. virustotal_communicating_files(\"ip\", {seed_value})\n"
            f"9. threatfox_search({seed_value})\n"
            f"10. otx_ip({seed_value})\n"
            "BEST-EFFORT (call but skip cleanly if tier_restricted=true):\n"
            f"  - onyphe_threatlist({seed_value})\n"
            f"  - onyphe_resolver_reverse({seed_value})\n"
            "JARM PIVOT (MANDATORY if a non-CDN JARM was extracted):\n"
            f"  - shodan_search(\"ssl.jarm:<jarm>\")        (paid, may be tier_restricted)\n"
            f"  - onyphe_datascan(\"jarm:<jarm>\")          (paid, may be tier_restricted)\n"
            f"  - urlscan_search(\"hash:<jarm>\")           (FREE, ALWAYS call this)\n"
            "  CLUSTER GRAPHING RULE: for EACH distinct IP in the union of shodan/onyphe/urlscan\n"
            "  hits, add_node(ip, <ip>) + add_edge(seed→<ip>, same_jarm, source=<s|o|urlscan>).\n"
            "  Graph the top 10 by ASN diversity. A prose summary without nodes is a graph failure.\n"
            "CERT PIVOT (MANDATORY if virustotal_ip returned a cert serial or issuer.O):\n"
            f"  - crtsh_serial(<cert_serial>)  (FREE, always call). For each host in digest.hosts\n"
            "    not already in graph: add_node(domain|ip, <h>) + add_edge(seed→<h>, same_cert,\n"
            "    source=\"crtsh\", evidence=\"crt.sh serial=<serial>\").\n"
            "  - If issuer.O is distinctive and not a CA (e.g. not DigiCert/LetsEncrypt/Sectigo/GoDaddy):\n"
            f"    crtsh_query(\"<issuer_O>\", match=\"ILIKE\")  → graph each new CN as above with same_cert.\n"
            "FALLBACK: If virustotal_communicating_files returns empty data[] and threatfox/otx "
            "identify a specific malware family, call malwarebazaar_signature(<family>) "
            "and add each returned sample as a hash node with a communicates_with edge to the seed IP."
        )
    elif seed_type == "jarm":
        user_prompt = (
            f"Seed indicator: type=jarm value={seed_value}\n"
            "This is a TLS JARM fingerprint. Follow the JARM workflow from the system prompt.\n"
            "You MUST call ALL of these tools before writing the report:\n"
            f"1. add_node(jarm, {seed_value}, tags=[\"seed\"])\n"
            f"2. shodan_search(\"ssl.jarm:{seed_value}\")\n"
            f"3. urlscan_search(\"hash:{seed_value}\")\n"
            f"4. For top 3 diverse IPs (different ASN/org): defuse + rdap_ip + virustotal_ip + threatfox_search\n"
            f"5. threatfox_search({seed_value})\n"
            "Every host with the same JARM must be graphed (ip node + has_jarm edge).\n"
            "If the cluster has >200 members, note 'common_jarm_likely_cdn' and keep 10 representatives.\n"
            "Write the report last with value=\"investigation_summary\"."
        )
    elif seed_type == "asn":
        asn_num = seed_value.upper().removeprefix("AS") or seed_value
        user_prompt = (
            f"Seed indicator: type=asn value={seed_value}\n"
            "This is an Autonomous System Number. Follow the ASN workflow from the system prompt.\n"
            "You MUST call ALL of these tools before writing the report:\n"
            f"1. add_node(asn, {seed_value}, tags=[\"seed\"])  (use the canonical AS<digits> form)\n"
            f"2. shodan_search(\"asn:AS{asn_num} port:443\")  — narrows to the web-facing slice\n"
            f"3. For top 5 most interesting IPs (unusual JARM / non-generic title / unusual ports):\n"
            f"   defuse + virustotal_ip + threatfox_search + otx_ip\n"
            f"4. rdap_ip on ONE representative IP from the ASN to capture netname/country/abuse_email\n"
            f"   MANDATORY: add_node(country, <ISO2>) + add_edge(asn→country, located_in)\n"
            f"5. threatfox_search(\"AS{asn_num}\")\n"
            "If multiple hosts inside the AS share the same JARM, graph the JARM node and link\n"
            "every matching IP to it. Tag the asn 'abused_asn' when ≥2 hosts return detection hits.\n"
            "Write the report last with value=\"investigation_summary\"."
        )
    elif seed_type == "executable_name":
        user_prompt = (
            f"Seed indicator: type=executable_name value={seed_value}\n"
            "This is JUST the filename of a malicious binary — the analyst does\n"
            "NOT have the file itself and does NOT have its hash. Your job is to\n"
            "find sample(s) ever reported under this filename and attribute the\n"
            "family from there. There is no fingerprint to pivot on yet — the\n"
            "filename is the only signal.\n\n"
            f"STEP 1: add_node(executable_name, {seed_value}, tags=[\"seed\"], "
            f"metadata={{\"extension\": \"<ext>\"}})\n"
            f"STEP 2: malwarebazaar_filename({seed_value})  — primary pivot. "
            "For EACH sample returned (up to the top 10, prioritising distinct\n"
            f"  sha256/signature/file_type triplets):\n"
            "  - add_node(hash, <sha256_hash>, metadata={file_name, file_type, "
            "signature, first_seen}, source=\"malwarebazaar\")\n"
            f"  - add_edge(<hash> → executable_name node, observed_as, "
            f"source=\"malwarebazaar\", evidence=\"reported with filename "
            f"{seed_value} on MalwareBazaar\")\n"
            "  - If `signature` is set on the sample, that is the malware family\n"
            "    — copy it onto the executable_name node as a tag (e.g. "
            "    'family:agenttesla', 'family:lummac2') and add an `attributed_to`\n"
            "    relation in the report's metadata.\n"
            f"STEP 3: For the top 3 sample hashes (by recency / family diversity), "
            "run the full hash workflow:\n"
            "  - virustotal_file(<h>)  — extract names[], meaningful_name, "
            "first_submission, family from popular_threat_classification\n"
            "  - malwarebazaar_hash(<h>)  — yara/cape tags, C2 list\n"
            "  - otx_file(<h>)  — pulse / actor attribution\n"
            "  - threatfox_search(<h>)  — IOCs linked to that sample\n"
            "  Graph every C2 / contacted_url / contacted_domain / "
            "contacted_ip the sample reveals (add_node + communicates_with edge).\n"
            f"STEP 4: threatfox_search({seed_value})  — sometimes ThreatFox\n"
            "  entries reference filenames as IOCs (especially for droppers).\n"
            f"STEP 5: opencti_lookup_indicator({seed_value})  — community KG\n"
            "  may have the filename indexed against an actor / campaign.\n"
            "STEP 6: If no sample is found in MalwareBazaar AND threatfox finds\n"
            "  no hit, the filename may be too generic ('update.exe', "
            "  'svchost.exe', 'taskmgr.exe') — note that explicitly in the\n"
            "  report's metadata under `attribution_status: \"filename_too_"
            "generic\"` and STILL write a short investigation_summary.\n"
            "STEP 7: Final report — value=\"investigation_summary\", linking the\n"
            "  executable_name node with known_ioc. The summary MUST state:\n"
            "  - how many samples were found,\n"
            "  - the dominant malware family (if any),\n"
            "  - the most distinctive C2 / network IOC each family contacts,\n"
            "  - whether the filename is generic / shared across families.\n"
            "EXCEPTION: If malwarebazaar_filename returns zero samples and the\n"
            "  filename matches a known legitimate binary (svchost, explorer,\n"
            "  notepad, chrome, msedge…), tag the seed `generic_filename` and\n"
            "  keep the report minimal — explain that the name alone is not a\n"
            "  meaningful pivot."
        )
    elif seed_type == "email":
        user_prompt = (
            f"Seed indicator: type=email value={seed_value}\n"
            "This is an email address — most often a malware/phishing registrant\n"
            "contact, a C2 beacon target, an exfil drop, or a paste-site author.\n"
            "Your job is to find every domain registered with this email, every\n"
            "reputation signal, and any threat-intel mention.\n\n"
            f"STEP 1: add_node(email, {seed_value}, tags=[\"seed\"])\n"
            f"STEP 2: emailrep_check({seed_value})  — reputation, disposable flag,\n"
            "        spammer / malicious tags. Copy `details.profiles` onto the node\n"
            "        metadata when present (linked social profiles).\n"
            f"STEP 3: whoxy_reverse(email=\"{seed_value}\")  — every domain ever\n"
            "        registered with this email. For each returned domain (top 25\n"
            "        prioritising recency / TLD diversity):\n"
            "          - add_node(domain, <d>)\n"
            "          - add_edge(email→domain, registered, source=\"whoxy\")\n"
            "        Tag the email `bulk_registrant` if ≥20 domains are returned.\n"
            f"STEP 4: pulsedive_indicator({seed_value}) — risk-scored corroboration.\n"
            f"STEP 5: opencti_lookup_indicator({seed_value}) — community KG hits.\n"
            f"STEP 6: threatfox_search({seed_value}) — listed as IOC?\n"
            "STEP 7: For the TOP 3 domains discovered in STEP 3 (most recently\n"
            "        registered or most-suspect TLD), run the full domain workflow\n"
            "        (rdap, dns, VT, urlhaus, threatfox, otx) so the cluster has\n"
            "        concrete infrastructure to pivot from.\n"
            "STEP 8: Final report — value=\"investigation_summary\". The summary\n"
            "        MUST state: how many domains the email registered, whether the\n"
            "        email is disposable / reputation-flagged, and the dominant\n"
            "        malware family or campaign (if attributable)."
        )
    elif seed_type == "wallet_address":
        user_prompt = (
            f"Seed indicator: type=wallet_address value={seed_value}\n"
            "This is a cryptocurrency wallet address — most often a ransomware\n"
            "payment target, a scam-collection wallet, or a market vendor wallet.\n"
            "We do not (yet) query block explorers — your job is to surface every\n"
            "PUBLIC threat-intel mention of this address and graph the surrounding\n"
            "infrastructure so analysts can attribute the campaign.\n\n"
            f"STEP 1: add_node(wallet_address, {seed_value}, tags=[\"seed\"], "
            f"metadata={{\"chain\": \"<btc|eth|xmr|...>\"}})\n"
            "        Set the chain in metadata based on the address format:\n"
            "          - 0x + 40 hex   → ethereum (also BSC, Polygon — flag both)\n"
            "          - bc1/tb1       → bitcoin (bech32)\n"
            "          - 1 / 3 + b58   → bitcoin (legacy P2PKH / P2SH)\n"
            "          - 4 / 8 + b58   → monero\n"
            f"STEP 2: threatfox_search({seed_value}) — abuse.ch lists wallets in\n"
            "        ransomware IOC bundles. Every matching threat_type / malware\n"
            "        field becomes a tag on the wallet_address node.\n"
            f"STEP 3: pulsedive_indicator({seed_value}) — risk + linked indicators.\n"
            f"STEP 4: opencti_lookup_indicator({seed_value}) — community KG.\n"
            f"STEP 5: urlscan_search(\"{seed_value}\") — sometimes the address shows\n"
            "        up in scanned phishing page DOM (donate buttons, ransom notes).\n"
            "        For each matching page graph it as a url node and tie back to\n"
            "        the wallet with an embedded_in edge.\n"
            "STEP 6: Final report — value=\"investigation_summary\". The summary\n"
            "        MUST state: the chain, whether the wallet has any direct\n"
            "        threat-feed listing, and the campaign / malware family it is\n"
            "        attributed to (if known). If NONE of the sources return a\n"
            "        hit, set metadata.attribution_status=\"unattributed\" and keep\n"
            "        the report minimal. Without block-explorer access we cannot\n"
            "        chain-trace — note that explicitly in `limitations`."
        )
    elif seed_type == "username":
        user_prompt = (
            f"Seed indicator: type=username value={seed_value}\n"
            "This is an actor handle / alias — could be a forum username, a\n"
            "Telegram/X/GitHub handle, a malware-builder identifier, or a paste-\n"
            "site author. Treat it as an opaque identifier and surface every\n"
            "public mention in the threat-intel sources we have.\n\n"
            f"STEP 1: add_node(username, {seed_value}, tags=[\"seed\"])\n"
            f"STEP 2: threatfox_search({seed_value}) — sometimes lists known actor handles.\n"
            f"STEP 3: pulsedive_indicator({seed_value}) — corroboration.\n"
            f"STEP 4: opencti_lookup_indicator({seed_value}) — community KG.\n"
            f"STEP 5: urlscan_search(\"{seed_value}\") — the handle may appear in\n"
            "        page text on phishing kits or open-dir listings.\n"
            "STEP 6: For every domain / IP / hash mentioned in returned records,\n"
            "        graph it (add_node + uses_handle edge from the infrastructure\n"
            "        back to the username node).\n"
            "STEP 7: Final report — value=\"investigation_summary\". The summary\n"
            "        MUST state: which actor / campaign the handle attributes to\n"
            "        (if any), how many concrete IOCs were tied to it, and what\n"
            "        platforms / forums the handle has been observed on. If no\n"
            "        public source mentions the handle, set\n"
            "        metadata.attribution_status=\"no_public_record\" and keep\n"
            "        the report minimal — the handle alone is not actionable."
        )
    elif seed_type == "command_line":
        user_prompt = (
            f"Seed indicator: type=command_line value={seed_value}\n"
            "This is a malicious command line / script / dropper snippet pasted "
            "by the analyst. The raw text is in the SOURCE REPORT block above — "
            "read it carefully BEFORE anything else.\n\n"
            f"STEP 1: add_node(command_line, {seed_value}, tags=[\"seed\"], "
            f"metadata={{\"preview\": \"<first line>\", \"interpretation\": "
            f"\"<one sentence: what does this command do>\"}})\n"
            "STEP 2: Categorise the command. Pick one and add it as a tag:\n"
            "  - powershell_dropper | bash_dropper | living_off_the_land | "
            "lolbins | base64_loader | hta_dropper | mshta_dropper | "
            "certutil_download | bitsadmin | curl_pipe_bash | iex_download | "
            "obfuscated_script\n"
            "STEP 3: Identify EVERY embedded indicator and graph it as its own node:\n"
            "  - URLs (curl/wget/Invoke-WebRequest/DownloadString targets) → "
            "add_node(url, <url>), add_edge(command_line→url, embedded_in_command)\n"
            "  - IPs / domains → add_node + same edge\n"
            "  - Hashes → add_node(hash, <h>) + same edge\n"
            "  - Base64 blobs that decode to URLs/IPs → decode mentally, add the\n"
            "    decoded indicator as a node + edge with evidence=\"decoded from\n"
            "    base64 within command line\".\n"
            "  - LOLBin names (rundll32, mshta, regsvr32, certutil, bitsadmin,\n"
            "    msbuild, installutil, …) → tag the command_line node with the\n"
            "    lolbin name; no separate node needed.\n"
            "STEP 4: For each embedded URL / domain / IP, run its standard\n"
            "  workflow (urlscan_search + urlhaus_host + virustotal_* + threatfox_search).\n"
            "STEP 5: If a binary hash is referenced or downloaded, run\n"
            "  virustotal_file(<h>) + malwarebazaar_hash(<h>) + otx_file(<h>) to\n"
            "  identify the family.\n"
            "STEP 6: Final report — value=\"investigation_summary\", linking the\n"
            "  command_line node with known_ioc. The summary MUST describe what\n"
            "  the command does AND which family / actor the embedded infrastructure\n"
            "  belongs to (if attributable)."
        )
    else:
        user_prompt = (
            f"Seed indicator: type={seed_type} value={seed_value}\n"
            "Investigate now. MANDATORY tools (must all run before the report):\n"
            f"1. rdap_domain/dns_resolve({seed_value})\n"
            f"2. crtsh_subdomains({seed_value})\n"
            f"3. virustotal_domain({seed_value})  — extract JARM, last_analysis_stats, categories\n"
            f"4. virustotal_resolutions_domain({seed_value})  — historical IPs\n"
            f"5. virustotal_communicating_files(\"domain\", {seed_value})\n"
            f"6. onyphe_domain({seed_value})  — community-tier ok. Iterate digest:\n"
            f"   for each ip in digest.ips / jarm in digest.jarms / sub in digest.subdomains /\n"
            f"   feed in digest.threat_feeds → add_node + add_edge with source=\"onyphe\".\n"
            f"7. threatfox_search({seed_value})\n"
            f"8. otx_domain({seed_value})\n"
            "BEST-EFFORT (call but skip cleanly if tier_restricted=true):\n"
            f"  - onyphe_ctl({seed_value})  — CT log SANs (each new → add_node(domain)+same_cert edge)\n"
            f"  - onyphe_resolver_forward({seed_value})  — alt-pDNS\n"
            "JARM / FAVICON pivots (if extracted and not a CDN value):\n"
            "  - shodan_search(\"ssl.jarm:<jarm>\") and onyphe_datascan(\"jarm:<jarm>\")\n"
            "  - shodan_search(\"http.favicon.hash:<hash>\") and onyphe_datascan(\"favicon:<hash>\")\n"
            "  Graph every cluster IP with a same_jarm/same_favicon edge. If BOTH sources return\n"
            "  tier_restricted=true, note it in pivot_suggestions and keep going.\n"
            "EXCEPTION: If step 1 shows the domain is clearly parked (parking NS + broker registrant), "
            "skip steps 2-8 and write a minimal report.\n"
            "FALLBACK: If communicating_files returns empty data[] and OTX/threatfox identifies a malware family, "
            "call malwarebazaar_signature(<family>) to find known samples and add them as hash nodes."
        )

    # If we got a CTI report PDF, prepend its text as ground truth context.
    # The agent reads it BEFORE running tools so attribution, relationships,
    # and tags reflect what the report actually says — not just regex hits.
    if report_context:
        # Trim defensively. ~30k chars ≈ 7-10 pages, well within context budget.
        ctx = report_context.strip()
        if len(ctx) > 30_000:
            ctx = ctx[:30_000] + "\n…[truncated]"
        user_prompt = (
            "SOURCE REPORT (verbatim, treat as ground truth for this investigation):\n"
            "═══════════════════════════════════════════════════════════════════\n"
            f"{ctx}\n"
            "═══════════════════════════════════════════════════════════════════\n\n"
            "How to use this report:\n"
            "- Encode every relationship the report STATES (X→Y, X used by actor A, "
            "campaign C uses domain D) as edges with relation reflecting the report's "
            "language (e.g. 'attributed_to', 'used_by_campaign', 'observed_dropping', "
            "'communicates_with') and source=\"report\". Add the matching evidence quote.\n"
            "- Add a tag on the seed and on actor / malware / campaign nodes "
            "(e.g. 'apt-name', 'malware-family') taken VERBATIM from the report.\n"
            "- Create the actor / campaign / malware family as a node when named "
            "(reuse type 'report' for actor profiles or, when better fitting, "
            "use 'domain' for hostnames already named).\n"
            "- Cross-check tool output against the report. If they disagree, prefer "
            "the report's framing in the summary, but keep the tool's raw evidence.\n"
            "- Do NOT invent content not in the report or in tool results.\n"
            "- After encoding the report's stated facts, run the standard MANDATORY "
            "workflow below on the seed to enrich and validate.\n\n"
            "─── Standard investigation prompt for this seed ───────────────────\n"
            + user_prompt
        )

    env = _build_env(inv_id)
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"cwd": str(ROOT), "mcp_config": str(mcp_cfg_path)})

    # ── Phase 1: Main investigation ──
    # Gate against a known cooldown — if a previous run already hit the
    # subscription limit and we're still inside the window, refuse to spawn
    # the agent (it would only burn another error).
    blocked, reset_at, msg = quota_block_active()
    if blocked:
        _log(inv_id, "agent_skipped_quota", {"reset_at": reset_at, "message": msg})
        _finalise_quota_halt(inv_id, {"reset_at": reset_at, "message": msg})
        return

    rc, saw_result, has_report, quota = await _run_claude_phase(
        inv_id, user_prompt, SYSTEM_PROMPT, model, env, mcp_cfg_path,
        phase="main"
    )

    if quota["hit"]:
        _finalise_quota_halt(inv_id, quota)
        return

    phase1_ok = saw_result or has_report or rc == 0

    # ── Phase 1.5: Mechanical working_hypothesis enforcement ──
    # The hypothesis-first arc in SYSTEM_PROMPT is read but inconsistently
    # acted on (9/12 cases skipped it on 2026-05-05). Without the hypothesis
    # node, the per-category playbooks (apt_targeted sibling-enum,
    # traffer_or_tds vt_pdns deep-dive, etc.) never trigger. Force the
    # commit by running a small dedicated prompt phase if absent. Skip on
    # parked seeds (no useful enrichment possible).
    def _has_working_hypothesis() -> bool:
        try:
            g = gs.get_graph(inv_id)
            for n in g.get("nodes", []):
                if (n.get("type") or "").lower() != "report":
                    continue
                v = (n.get("value") or "").lower()
                if v == "working_hypothesis" or v.startswith("working_hypothesis"):
                    return True
        except Exception:
            return False
        return False

    if phase1_ok and not _is_parked(inv_id) and not _has_working_hypothesis():
        _log(inv_id, "phase_hypothesis_write_needed", {})
        hypothesis_prompt = (
            f"You completed phase 1 of the investigation on seed "
            f"{seed_type}={seed_value} but did NOT write a "
            f"working_hypothesis report node. Per the hypothesis-first "
            f"loop in your system prompt, this is REQUIRED before phase 2 "
            f"can pursue category-specific pivots.\n\n"
            f"STEP 1: Call get_graph(compact=True) to see what phase 1 found.\n"
            f"STEP 2: Pick exactly ONE category from this list, based on the "
            f"strongest evidence in the graph:\n"
            f"  - apt_targeted        (state-aligned, named actor, narrow targeting)\n"
            f"  - commodity_malware   (Amadey/StealC/Lumma/Bumblebee — broad, financial)\n"
            f"  - traffer_or_tds      (SocGholish/Keitaro/redirector chains)\n"
            f"  - phishing_kit        (Tycoon/Lighthouse/Storm-1747 PhaaS)\n"
            f"  - infostealer         (Lumma/Vidar/RedLine/Raccoon)\n"
            f"  - post_ex_framework   (Cobalt Strike/Sliver/AdaptixC2/Eye Pyramid)\n"
            f"  - smishing            (USPS/toll/E-ZPass — Smishing Triad)\n"
            f"  - sinkholed           (LE/Microsoft/DOJ takedown — preserve passive residue)\n"
            f"  - parked_or_squatted  (no malicious activity, defuse)\n"
            f"  - unclear             (insufficient evidence — call this honestly)\n\n"
            f"STEP 3: add_node(\"report\", \"working_hypothesis\", metadata={{\n"
            f"   \"category\": \"<one of the above>\",\n"
            f"   \"confidence\": \"low|medium|high\",\n"
            f"   \"reason\": \"<one sentence citing the strongest 1-2 graph signals>\",\n"
            f"   \"evidence\": [\"<concrete signal 1>\", \"<concrete signal 2>\"],\n"
            f"   \"what_to_pursue_next\": [\"<pivot 1>\", \"<pivot 2>\"]\n"
            f"}}, source=\"agent\", tags=[\"report\", \"hypothesis\"]).\n\n"
            f"DO NOT call any CTI tool. DO NOT investigate further. Just read "
            f"the existing graph, pick the category, write the node, return.\n"
            f"This must be exactly ONE add_node call followed by an end-of-turn."
        )
        try:
            # Phase 1.5 used max_turns=4 + _FOLLOWUP_SYSTEM_PROMPT before, which
            # caused 11/12 cases on 2026-05-06 to fail. Two issues:
            # (a) the followup prompt explicitly forbade creating report nodes
            #     — directly contradicting this phase's task (write the
            #     working_hypothesis report node);
            # (b) the agent burned 1-3 turns on ToolSearch before reaching the
            #     2 calls it actually needs (get_graph → add_node), exceeding
            #     the 4-turn budget.
            # Fix: dedicated permissive system prompt + 8-turn budget.
            rc_h, saw_h, _, quota_h = await _run_claude_phase(
                inv_id, hypothesis_prompt, _HYPOTHESIS_SYSTEM_PROMPT, model,
                env, mcp_cfg_path, phase="hypothesis_write", max_turns=8,
            )
            _log(inv_id, "phase_hypothesis_write_done", {
                "rc": rc_h, "saw_result": saw_h,
                "wh_present_after": _has_working_hypothesis(),
            })
            if quota_h["hit"]:
                _finalise_quota_halt(inv_id, quota_h)
                return
        except Exception as e:
            _log(inv_id, "phase_hypothesis_write_error", {"error": str(e)[:300]})

    # ── Phase 2: Follow-up for missing mandatory tools + adaptive Phase 3 gaps ──
    if phase1_ok and not _is_parked(inv_id):
        called = _get_called_cti_tools(inv_id)
        missing = _missing_mandatory_tools(seed_type, seed_value, called)
        adaptive_targets = _adaptive_followup_targets(inv_id)
        # Promote cert-CN origin-unmask from adaptive hints to mandatory.
        # The CDN Cloudflare-defuse pivot (shodan_search("ssl.cert.subject.CN:...")
        # + onyphe_datascan("tls.cert.subject.commonname:...")) was classified as
        # an adaptive suggestion but the agent repeatedly ignores it even when
        # explicitly listed. Elevating it to mandatory gives it the "MUST call"
        # enforcement language in the followup prompt. Affects Cases 11 + 12
        # (canonical Cloudflare-defuse: PS 50→100 on c12, CDN-origin-unmask test).
        _cn_unmask = [t for t in adaptive_targets if any(
            "ssl.cert.subject.cn" in c.lower()
            or "tls.cert.subject.commonname" in c.lower()
            for c in t[2]
        )]
        if _cn_unmask:
            for _, _, _calls, _ in _cn_unmask:
                missing.extend(_calls)
            adaptive_targets = [t for t in adaptive_targets if t not in _cn_unmask]
        if missing or adaptive_targets:
            _log(inv_id, "phase2_needed", {
                "missing": missing,
                "adaptive_targets_count": len(adaptive_targets),
                "called": sorted(called),
            })
            # Build extra follow-up steps for IP/domain seeds
            extra_steps = []
            if seed_type == "ip":
                extra_steps.append(
                    "After the above: read the graph — if a JARM node exists for this IP, "
                    "call shodan_search(\"ssl.jarm:<jarm_value>\") to find other IPs with the same fingerprint. "
                    "Add any new IPs as nodes with same_jarm edges to the seed IP."
                )
                extra_steps.append(
                    "If virustotal_communicating_files returned an empty data[] AND threatfox/otx "
                    "identified a specific malware family tag, "
                    "call malwarebazaar_signature(<family>, limit=5) and add each returned sample "
                    "as a hash node with a communicates_with edge from hash to the seed IP."
                )
                extra_steps.append(
                    "If reverse_dns returned ≥ 1 domain, for EACH returned domain (top 3): "
                    "(a) dns_resolve(<domain>, 'MX') and dns_resolve(<domain>, 'TXT') — add each "
                    "discovered MX hostname and TXT record value to the seed/domain metadata; "
                    "(b) crtsh_subdomains(<domain>) to enumerate sister hostnames; "
                    "(c) wayback(<domain>) to check for historical takedown/seizure notices. "
                    "Add every discovered hostname as a new domain node with edge "
                    "(seed_ip → domain, resolves_to) and (domain → wayback_snapshot, has_archive)."
                )
            elif seed_type == "domain":
                extra_steps.append(
                    "If virustotal_communicating_files returned an empty data[] AND threatfox/otx "
                    "identified a specific malware family tag, "
                    "call malwarebazaar_signature(<family>, limit=5) and add each returned sample "
                    "as a hash node with a communicates_with edge from hash to the seed."
                )
            steps_block = ""
            if extra_steps:
                steps_block = "\n\nThen, as additional REQUIRED follow-up steps:\n" + "\n".join(
                    f"  {i + len(missing) + 1}. {s}" for i, s in enumerate(extra_steps)
                )
            # Check if an investigation_summary already exists before phase 2.
            # If not, the followup MAY write one; if it exists, the followup
            # must update it in place (add_node upserts on (inv,type,value)).
            try:
                g_pre2 = gs.get_graph(inv_id)
                has_summary_pre2 = any(
                    (n.get("type") or "").lower() == "report"
                    and (n.get("value") or "").lower() == "investigation_summary"
                    for n in g_pre2.get("nodes", [])
                )
            except Exception:
                has_summary_pre2 = False

            report_instr = (
                "A final investigation_summary report node already exists — "
                "do NOT create a second one. If you have new findings, update "
                "it in place by calling add_node with the canonical value "
                "\"investigation_summary\" (upsert)."
                if has_summary_pre2 else
                "No investigation_summary report node exists yet. After "
                "running the missed tools above, you MUST write one: "
                "add_node(report, \"investigation_summary\", metadata={...}, "
                "source=\"agent\", tags=[\"report\"]) per STEP 8 of the main "
                "workflow, then add_edge(seed→report, known_ioc)."
            )
            already_called_list = sorted(called)

            # Build the adaptive Phase 3 gap section (per-graph-state, not a
            # static script). Each line names a node already in the graph and
            # the specific tool calls that would high-leverage-pivot on it.
            adaptive_block = ""
            if adaptive_targets:
                lines = []
                for i, (ntype, nvalue, calls, rationale) in enumerate(adaptive_targets, 1):
                    short_value = nvalue if len(nvalue) <= 60 else nvalue[:57] + "..."
                    line = (f"  {i}. {ntype} \"{short_value}\" — {' AND '.join(calls)}\n"
                            f"     [why: {rationale}]")
                    lines.append(line)
                adaptive_block = (
                    "\n\nADAPTIVE PHASE-3 GAPS — graph-state-aware pivots:\n"
                    "The following nodes are already in the graph but have NOT been pivoted with\n"
                    "newly-available Phase 3 sources. For EACH item, run the listed tool call(s)\n"
                    "and add the results to the graph (new nodes + edges from the parent node).\n"
                    "These are not optional — they are gaps where the main phase missed a\n"
                    "high-leverage pivot. Skip ONLY if the source returns no useful data, and\n"
                    "note the reason in the report's gaps_summary.\n\n"
                    + "\n".join(lines)
                )

            mandatory_section = ""
            if missing:
                mandatory_section = (
                    f"STEP 2-{len(missing)+1}: Call ONLY these CTI tools that were "
                    f"missed in phase 1 (do NOT substitute with any other tool, do "
                    f"NOT repeat already-called tools):\n"
                    + "\n".join(f"  {i+2}. {m}" for i, m in enumerate(missing))
                    + "\nFor each result, add new nodes and edges to the graph.\n"
                )
            else:
                mandatory_section = (
                    "All mandatory phase-1 tools were called. Focus on the adaptive\n"
                    "Phase-3 gaps below.\n"
                )

            # Surface the chosen working_hypothesis category to anchor phase 2
            # pivot decisions. Without this, the agent sometimes ignores the
            # hypothesis it just committed to.
            hypothesis_block = ""
            try:
                g_pre2_h = gs.get_graph(inv_id)
                for n in g_pre2_h.get("nodes", []):
                    if (n.get("type") or "").lower() != "report":
                        continue
                    v = (n.get("value") or "").lower()
                    if v == "working_hypothesis" or v.startswith("working_hypothesis"):
                        md = n.get("metadata") or {}
                        cat = md.get("category", "?")
                        conf = md.get("confidence", "?")
                        what = md.get("what_to_pursue_next") or []
                        what_str = "; ".join(str(w) for w in what[:5]) if isinstance(what, list) else str(what)
                        hypothesis_block = (
                            f"\nYOUR WORKING HYPOTHESIS (committed in phase 1.5):\n"
                            f"  category={cat}  confidence={conf}\n"
                            f"  what_to_pursue_next: {what_str or '(none specified)'}\n"
                            f"Phase 2 pivot decisions MUST advance this hypothesis. If new "
                            f"evidence contradicts it, OVERWRITE the working_hypothesis node "
                            f"with the revised category and reason (do not silently switch).\n"
                        )
                        break
            except Exception:
                pass

            # Cluster-class hypotheses (phishing_kit, smishing, drainer,
            # traffer/TDS, fronted C2) all share the same disease: the main
            # phase finds 1-3 siblings via cert/JARM and stops, leaving the
            # bulk of the cluster invisible until the analyst manually says
            # "go further". Detect that case here and inject an explicit
            # recursive-expansion directive — "every new sibling you graph
            # is itself a fresh seed for title/favicon/cert pivots, keep
            # going until next_pivot returns nothing new."
            cluster_categories = {
                "phishing_kit_cluster", "phishing_kit", "smishing_hub",
                "smishing", "traffer_or_tds", "drainer_kit", "fronted_c2",
            }
            is_cluster_hypothesis = False
            try:
                for n in gs.get_graph(inv_id).get("nodes", []):
                    if (n.get("type") or "").lower() != "report":
                        continue
                    v = (n.get("value") or "").lower()
                    if v == "working_hypothesis" or v.startswith("working_hypothesis"):
                        md = n.get("metadata") or {}
                        cat = (md.get("category") or md.get("candidate_category")
                               or "").lower()
                        if cat in cluster_categories:
                            is_cluster_hypothesis = True
                        break
            except Exception:
                pass

            cluster_directive = ""
            if is_cluster_hypothesis:
                cluster_directive = (
                    "\n\nCLUSTER-EXPANSION DIRECTIVE (your hypothesis is a kit-templated "
                    "or fan-out cluster):\n"
                    "  Every page_title, favicon_hash, tracking_id, cert serial, and "
                    "url-path-template is a CLUSTER-EXPANSION pivot. For each one:\n"
                    "    1) urlscan_search(\"page.title:\\\"<title>\\\"\", size=200) — siblings using the same kit template\n"
                    "    2) urlscan_search(\"page.url:/<distinctive-path>/\") — siblings using the same URL path\n"
                    "    3) shodan_search(\"http.favicon.hash:<hash>\") + netlas_favicon + zoomeye_favicon\n"
                    "  After EACH urlscan/shodan/netlas hit list, add EVERY distinct sibling domain "
                    "or IP as a node with a same_template/same_favicon/same_jarm edge. Do NOT "
                    "summarise the cluster in prose — graph every member.\n"
                    "  Recurse: each new sibling is itself a fresh seed for title/favicon pivots if "
                    "it surfaces a NEW title/favicon/path. Stop only when one full pass adds zero "
                    "new nodes. The default behaviour of stopping after the first batch is what we "
                    "are explicitly preventing here.\n"
                )

            followup_prompt = (
                f"Continue the investigation on {seed_value} (type={seed_type}). "
                f"The graph already has nodes from the main investigation.\n\n"
                f"ALREADY CALLED (DO NOT re-run any of these, their results are "
                f"already in the graph):\n  "
                + ", ".join(already_called_list or ["(none)"]) + "\n\n"
                + hypothesis_block
                + f"STEP 1: Call get_graph(compact=True) to see what already exists.\n"
                + mandatory_section
                + adaptive_block
                + cluster_directive
                + "\n\n" + report_instr
                + steps_block
            )
            # Phase 2 budget: 30 turns was too tight for cluster-class
            # hypotheses (phishing_kit_cluster / smishing_hub /
            # traffer_or_tds) where each adaptive target plus the recursive
            # expansion (urlscan title pivot → 30+ siblings → graph each as
            # a node) easily eats 50+ tool calls. 60 turns gives us
            # headroom without unbounded runaway.
            rc2, saw2, _, quota2 = await _run_claude_phase(
                inv_id, followup_prompt, _FOLLOWUP_SYSTEM_PROMPT, model, env,
                mcp_cfg_path, phase="followup", max_turns=60
            )
            _log(inv_id, "phase2_done", {"rc": rc2, "saw_result": saw2})
            if quota2["hit"]:
                _finalise_quota_halt(inv_id, quota2)
                return

            # Check what was actually called now
            called_after = _get_called_cti_tools(inv_id)
            still_missing = _missing_mandatory_tools(seed_type, seed_value, called_after)
            if still_missing:
                _log(inv_id, "phase2_incomplete", {"still_missing": still_missing})

    # ── Phase 3: Report-write fallback ──
    # If after main (+ optional followup) no investigation_summary report node
    # exists, run a dedicated single-purpose phase that writes ONE report node
    # and nothing else. This catches the case where the main agent terminated
    # before STEP 8 and the followup was told "do not create a new report".
    def _has_investigation_summary() -> bool:
        try:
            g = gs.get_graph(inv_id)
            return any(
                (n.get("type") or "").lower() == "report"
                and (n.get("value") or "").lower() == "investigation_summary"
                for n in g.get("nodes", [])
            )
        except Exception:
            return False

    if not _is_parked(inv_id) and not _has_investigation_summary():
        _log(inv_id, "phase3_report_write_needed", {})

        # Mechanically harvest discriminating-marker candidates from existing
        # graph metadata so the model is forced to copy them verbatim. Without
        # this the agent paraphrases ("a SHA1 cert was found") instead of
        # writing the actual hex string, costing RQ.
        marker_lines = []
        try:
            g_for_markers = gs.get_graph(inv_id)
            seen = set()
            for n in g_for_markers.get("nodes", []) or []:
                md = n.get("metadata") or {}
                # Surface specific high-signal fields, then any tag that looks
                # like a hex hash / cert serial.
                for k in ("cert_serial", "cert_sha1", "cert_subject_cn",
                          "subject_cn", "common_name", "jarm",
                          "favicon_hash", "favicon_mmh3",
                          "registrant_email", "registrant", "registrar",
                          "http_title", "page_title", "title",
                          "issuer_o", "asn", "as_org", "org",
                          "file_name", "meaningful_name"):
                    v = md.get(k)
                    if isinstance(v, str) and 4 < len(v) < 200:
                        item = f"{k}={v}"
                        if item not in seen:
                            seen.add(item)
                            marker_lines.append(item)
                for t in (n.get("tags") or []):
                    if isinstance(t, str) and len(t) >= 32 and re.match(r"^[a-f0-9]+$", t):
                        if t not in seen:
                            seen.add(t)
                            marker_lines.append(f"hex_marker={t}")
                # Also surface non-seed node values (cert/email types) directly
                nt = (n.get("type") or "").lower()
                nv = (n.get("value") or "")
                if nt in ("cert", "cert_cn", "email", "registrar") and nv:
                    item = f"{nt}={nv}"
                    if item not in seen:
                        seen.add(item)
                        marker_lines.append(item)
            marker_lines = marker_lines[:12]
        except Exception:
            marker_lines = []
        markers_block = ""
        if marker_lines:
            markers_block = (
                "\n\nMARKERS YOU MUST INCLUDE VERBATIM IN metadata.discriminating_markers "
                "AND MENTION THE STRONGEST ONE IN metadata.summary "
                "(copy the EXACT strings — do NOT paraphrase, truncate, or summarize):\n"
                + "\n".join(f"  • {m}" for m in marker_lines)
                + "\n"
            )

        report_prompt = (
            f"Write the final investigation_summary report node for seed "
            f"{seed_type}={seed_value}. The graph already has nodes and edges; "
            f"no CTI tools are required.\n\n"
            f"STEP 1: Call get_graph(compact=True) to see every node and edge. Then\n"
            f"  call get_report() for any existing report metadata. For nodes\n"
            f"  with important metadata (malware, IPs with detections, etc.),\n"
            f"  call get_node(type, value) to read their full metadata. Scan for:\n"
            f"  malware family names, actor aliases, campaign names, page titles,\n"
            f"  cert subject CNs, JARM fingerprints, favicon hashes, registrant\n"
            f"  emails, TTPs, threatfox/otx/urlhaus/virustotal threat_names.\n"
            f"STEP 2: Call add_node(report, \"investigation_summary\", metadata={{...}}, "
            f"source=\"agent\", tags=[\"report\"]) exactly ONCE. Use the canonical "
            f"value \"investigation_summary\" so the node is a singleton.\n"
            f"  - metadata.summary: 2-3 sentences. The summary MUST:\n"
            f"      • name the seed ({seed_value}) explicitly\n"
            f"      • name EVERY actor alias, malware family, ransomware strain,\n"
            f"        kit name, or campaign label that any graph node metadata\n"
            f"        mentions (threatfox malware_family, otx pulse names,\n"
            f"        urlhaus tags, virustotal threat_names, threat_feeds)\n"
            f"      • name the STRONGEST discriminating marker observed — the\n"
            f"        specific JARM fingerprint, cert subject CN, favicon hash,\n"
            f"        registrant email, page title, TDS query string, panel\n"
            f"        endpoint, or content signature that ties the seed to a\n"
            f"        cluster. Use the exact value, not \"a JARM\" or \"a cert\".\n"
            f"      • stay factual. R11 evidence rules apply to threat labels.\n"
            f"  - metadata.threat_assessment: benign|suspicious|likely_malicious|"
            f"malicious (R11 evidence rules apply).\n"
            f"  - metadata.key_findings: list of {{text, sources[]}}. Include one\n"
            f"    finding per strong marker (JARM match, cert serial, cross-\n"
            f"    brand page title, same NS set, registrant reuse, etc.).\n"
            f"  - metadata.ioc_list: exact node values from the graph. MUST list\n"
            f"    at least 70% of non-seed domain/ip/hash/email/url nodes.\n"
            f"  - metadata.discriminating_markers: the exact JARM / cert-CN /\n"
            f"    favicon / registrant values that would let a hunter re-pivot.\n"
            f"  - metadata.pivot_suggestions, sources_used.\n"
            f"STEP 3: add_edge(<seed_node_id>, <report_node_id>, known_ioc).\n"
            f"Do NOT call any CTI tool. Do NOT create a second report node. "
            f"Do NOT re-run enrichment."
            + markers_block
        )
        try:
            rc3, saw3, _, quota3 = await _run_claude_phase(
                inv_id, report_prompt, _FOLLOWUP_SYSTEM_PROMPT, model, env,
                mcp_cfg_path, phase="report_write", max_turns=6,
            )
            _log(inv_id, "phase3_report_write_done", {
                "rc": rc3, "saw_result": saw3,
                "report_written": _has_investigation_summary(),
            })
            if quota3["hit"]:
                _finalise_quota_halt(inv_id, quota3)
                return
        except Exception as e:
            _log(inv_id, "phase3_report_write_error", {"error": str(e)[:300]})
        # Mechanical completeness pass: append every IOC + harvested marker into
        # the summary metadata so RQ marker_hit + ioc_list 70% checks pass
        # regardless of how the model paraphrased the prose. The 2026-05-21
        # iteration measured 8/8 hypothesis-present cases falling RQ < 100 for
        # exactly this reason (model says "a JARM was found" instead of
        # writing the hex string in metadata.discriminating_markers).
        _enforce_summary_completeness(inv_id)

    # ── Phase 4: Autonomous pivot drain ──
    # The agent's report.metadata.pivot_suggestions is its own to-do list —
    # historically it sat there waiting for the analyst to manually click
    # "pivot" on each suggestion. Case study: prod inv 650c6884768c reached
    # 324 nodes via 39 manual pivots + 27 manual prompts; the autonomous
    # run on the same seed stopped at ≤40 nodes. This phase drains the
    # backlog the way the analyst would: read pivot_suggestions, queue,
    # gaps_report → execute the highest-leverage pivots → loop until a
    # round adds nothing new (or MAX_ROUNDS rounds, whichever comes first).
    #
    # Bounded by:
    #   - MAX_ROUNDS rounds (hard cap so we don't run forever)
    #   - max_turns per round (caps API spend per round)
    #   - convergence: delta_nodes < CONVERGENCE_THRESHOLD ⇒ stop
    # Skipped on parked seeds and when phase 1 didn't run.
    PIVOT_DRAIN_MAX_ROUNDS = int(os.environ.get("BOUNCE_PIVOT_DRAIN_ROUNDS", "3"))
    PIVOT_DRAIN_MAX_TURNS = int(os.environ.get("BOUNCE_PIVOT_DRAIN_MAX_TURNS", "60"))
    PIVOT_DRAIN_CONVERGENCE = int(os.environ.get("BOUNCE_PIVOT_DRAIN_CONVERGENCE", "3"))
    # Global CTI-call ceiling (EVAL_PROTOCOL §4.5 fast-triage budget). The drain
    # loop is the discretionary expansion phase; left unbounded it pushes complex
    # cases to 115-127 CTI calls (drain rounds overshoot because one agent turn
    # can emit several parallel tool_use blocks), which trips BD>90 → score 0.
    # We clamp each round's turn budget to the remaining global allowance and
    # stop draining once we're near the ceiling, landing in the ≤90 / BD-75 band
    # while preserving the early (high-yield) drain rounds. Set very high to
    # disable. Counts raw CTI tool_use blocks (same as the scorer).
    PIVOT_DRAIN_TOTAL_BUDGET = int(os.environ.get("BOUNCE_TOTAL_CTI_BUDGET", "82"))
    # Don't bother starting a round with less than this much headroom — too few
    # turns to make a meaningful dent, and avoids a multi-call overshoot landing
    # us above 90.
    PIVOT_DRAIN_MIN_HEADROOM = 8

    if (phase1_ok and not _is_parked(inv_id)
            and PIVOT_DRAIN_MAX_ROUNDS > 0):
        _log(inv_id, "phase_pivot_drain_starting", {
            "max_rounds": PIVOT_DRAIN_MAX_ROUNDS,
            "max_turns_per_round": PIVOT_DRAIN_MAX_TURNS,
            "convergence_threshold": PIVOT_DRAIN_CONVERGENCE,
            "total_cti_budget": PIVOT_DRAIN_TOTAL_BUDGET,
        })

        for round_idx in range(PIVOT_DRAIN_MAX_ROUNDS):
            # Global budget gate: stop draining when cumulative CTI calls
            # approach the ceiling; clamp this round to what's left.
            calls_so_far = _count_cti_calls(inv_id)
            remaining_budget = PIVOT_DRAIN_TOTAL_BUDGET - calls_so_far
            if remaining_budget < PIVOT_DRAIN_MIN_HEADROOM:
                _log(inv_id, "phase_pivot_drain_budget_stop", {
                    "round": round_idx + 1,
                    "cti_calls_so_far": calls_so_far,
                    "total_cti_budget": PIVOT_DRAIN_TOTAL_BUDGET,
                })
                break
            round_turns = min(PIVOT_DRAIN_MAX_TURNS, remaining_budget)
            # A single agent turn emits SEVERAL parallel `tool_use` blocks
            # (~2-3 CTI calls/turn), so `round_turns ≈ remaining_budget` (a
            # CALL count) under-restricts a near-ceiling round: Case 8 on the
            # 2026-05-31 run started a round at 74 calls with remaining=8 and
            # ran it out to 98 CTI calls → tripped the §4.5 `>90 ⇒ BD=0` cliff.
            # When the remaining allowance is small enough that a parallel burst
            # could blow past 90, re-budget the round in CALLS (÷ ~3 calls/turn).
            # Early, high-yield rounds (large remaining_budget) are unchanged, so
            # there is no coverage regression on complex cases that legitimately
            # spend 70-80 calls.
            if remaining_budget <= 24:
                round_turns = max(2, remaining_budget // 3)
            try:
                g_before = gs.get_graph(inv_id)
                n_before = len(g_before.get("nodes", []))
                e_before = len(g_before.get("edges", []))
            except Exception:
                n_before = 0
                e_before = 0

            # Pull current pivot_suggestions out of the report node — these
            # are the agent's own analyst-style next-step list. Trim to a
            # manageable size per round.
            pivot_sug_lines = []
            report_md_now = {}
            try:
                for n in gs.get_graph(inv_id).get("nodes", []):
                    if (n.get("type") or "").lower() == "report" and \
                       (n.get("value") or "").lower() == "investigation_summary":
                        report_md_now = n.get("metadata") or {}
                        break
                ps = report_md_now.get("pivot_suggestions") or []
                if isinstance(ps, list):
                    for p in ps[:8]:
                        if isinstance(p, str) and p.strip():
                            pivot_sug_lines.append(p.strip())
                        elif isinstance(p, dict):
                            # Some reports nest as {op, target, reason}
                            parts = [str(p.get(k)) for k in ("op", "target", "reason")
                                     if p.get(k)]
                            if parts:
                                pivot_sug_lines.append(" — ".join(parts))
            except Exception:
                pivot_sug_lines = []

            sug_block = ""
            if pivot_sug_lines:
                sug_block = (
                    "\n\nYOUR OWN PIVOT SUGGESTIONS (you wrote these in the report — "
                    "execute them now, do NOT just rewrite them):\n"
                    + "\n".join(f"  • {p}" for p in pivot_sug_lines)
                    + "\n"
                )

            drain_prompt = (
                f"AUTONOMOUS PIVOT DRAIN — round {round_idx + 1}/{PIVOT_DRAIN_MAX_ROUNDS}\n\n"
                f"You finished the main investigation on seed "
                f"{seed_type}={seed_value}. The analyst is NOT going to manually "
                f"click 'pivot' on each suggestion — your job is to drain your "
                f"own backlog autonomously until the graph stops growing.\n\n"
                f"STEP 1 (assess): Call get_graph(compact=True), get_report(), "
                f"queue_status(), and gaps_report() to see what's left.\n\n"
                f"STEP 2 (execute, in priority order):\n"
                f"  (a) Every entry in your report's pivot_suggestions that names "
                f"a specific IOC — run the named tool(s) on the named value.\n"
                f"  (b) For each ip/domain/cert/jarm/favicon_hash/title_hash node "
                f"that exists but has NOT been enriched with the type-appropriate "
                f"chain, run that chain now: ip → rdap_ip+abuseipdb_check+"
                f"criminalip_ip+virustotal_ip+onyphe_ip+virustotal_resolutions_ip+"
                f"shodan_host+threatfox_search; domain → rdap_domain+"
                f"virustotal_domain+threatfox_search+otx_domain+onyphe_domain; "
                f"cert with serial → certspotter_serial+crtsh_serial; "
                f"jarm → shodan_search+onyphe_datascan+netlas_jarm+zoomeye_jarm+"
                f"urlscan_search('hash:<jarm>'); favicon_hash → shodan_search("
                f"'http.favicon.hash:<h>')+netlas_favicon+zoomeye_favicon+"
                f"onyphe_datascan('favicon:<h>'); title_hash → urlscan_search("
                f"'page.title:\"<title>\"', size=200) for kit-template siblings.\n"
                f"  (c) For every value in metadata.discriminating_markers NOT "
                f"yet swept across all four scanner DBs, do the multi-source "
                f"sweep so each marker has at minimum 2 source corroborations.\n\n"
                f"STEP 3 (graph everything): Every new IOC returned MUST become a "
                f"node + edge with the canonical relation (same_cert / same_jarm "
                f"/ same_favicon / same_registrant / same_template / co_resolves). "
                f"Do NOT summarise unmade pivots in prose — graph the cluster.\n\n"
                f"STEP 4 (refresh the report at the end of the round): re-call "
                f"add_node(report, \"investigation_summary\", metadata={{...}}) "
                f"with the expanded ioc_list, refreshed pivot_suggestions, and "
                f"any new key_findings/discriminating_markers. The report is a "
                f"singleton — upsert it, do NOT create a second one.\n\n"
                f"BUDGET this round: ≈ {round_turns} tool calls. STOP "
                f"early if every remaining pivot would only return defused / "
                f"already-graphed values. The next round will pick up where you "
                f"left off if you didn't finish.\n"
                + sug_block
            )

            try:
                rc4, saw4, _, quota4 = await _run_claude_phase(
                    inv_id, drain_prompt, _FOLLOWUP_SYSTEM_PROMPT, model, env,
                    mcp_cfg_path, phase=f"pivot_drain_{round_idx + 1}",
                    max_turns=round_turns,
                )
                if quota4["hit"]:
                    _finalise_quota_halt(inv_id, quota4)
                    return
            except Exception as e:
                _log(inv_id, "phase_pivot_drain_error",
                     {"round": round_idx + 1, "error": str(e)[:300]})
                break

            try:
                g_after = gs.get_graph(inv_id)
                n_after = len(g_after.get("nodes", []))
                e_after = len(g_after.get("edges", []))
            except Exception:
                n_after = n_before
                e_after = e_before

            delta_n = n_after - n_before
            delta_e = e_after - e_before
            _log(inv_id, "phase_pivot_drain_round_done", {
                "round": round_idx + 1,
                "rc": rc4, "saw_result": saw4,
                "n_before": n_before, "n_after": n_after, "delta_n": delta_n,
                "e_before": e_before, "e_after": e_after, "delta_e": delta_e,
            })
            # Re-sync the summary metadata after each drain round so newly
            # graphed IOCs / markers immediately land in the canonical fields.
            _enforce_summary_completeness(inv_id)

            if delta_n < PIVOT_DRAIN_CONVERGENCE:
                _log(inv_id, "phase_pivot_drain_converged",
                     {"round": round_idx + 1, "delta_n": delta_n,
                      "convergence_threshold": PIVOT_DRAIN_CONVERGENCE})
                break

    # ── Phase 5: Lessons-learned retrospective ──
    # One-shot reflection pass: ask the agent what slowed it down and what
    # would have helped. The output lands both on the investigation graph
    # (as a hidden `lessons_learned` report node) and in the global ledger
    # `data/lessons_learned.jsonl` so a human can review aggregated feedback
    # across investigations. Runs even if earlier phases logged errors —
    # blocker reports are most valuable when something went wrong.
    if not _is_parked(inv_id) and not _has_lessons_learned(inv_id):
        try:
            lessons_prompt = (
                f"The investigation on {seed_type}={seed_value} is now "
                f"finished. Write the LESSONS-LEARNED retrospective node as "
                f"described in your system prompt. Focus on blockers, missing "
                f"capabilities, and concrete improvements you would make to "
                f"the codebase / MCP tools / prompts to make the NEXT "
                f"investigation faster and more accurate. Be brutally honest "
                f"about what slowed you down."
            )
            rc_l, saw_l, _, quota_l = await _run_claude_phase(
                inv_id, lessons_prompt, _LESSONS_LEARNED_SYSTEM_PROMPT,
                model, env, mcp_cfg_path, phase="lessons_learned",
                max_turns=6,
            )
            _log(inv_id, "phase_lessons_learned_done", {
                "rc": rc_l, "saw_result": saw_l,
                "ll_present_after": _has_lessons_learned(inv_id),
            })
            if quota_l["hit"]:
                _finalise_quota_halt(inv_id, quota_l)
                return
            # Persist whatever the agent wrote to the global JSONL ledger.
            _append_lessons_ledger(inv_id, seed_type, seed_value, model)
        except Exception as e:
            _log(inv_id, "phase_lessons_learned_error", {"error": str(e)[:300]})

    # ── Final status ──
    try:
        g = gs.get_graph(inv_id)
        has_report = any(n.get("type") == "report" for n in g.get("nodes", []))
    except Exception:
        has_report = False

    if saw_result or has_report or rc == 0:
        final_status = "done"
    else:
        final_status = f"error rc={rc}"
    gs.set_status(inv_id, final_status)
    # Emit a terminal event so the frontend's WebSocket loop can refresh
    # the sidebar status without needing a manual page reload.
    _log(inv_id, "agent_exit", {"rc": rc, "status": final_status, "has_report": has_report})


async def resume_investigation(inv_id: str, model: str = "opus"):
    """Pick a previously-halted investigation back up after the Claude
    subscription quota has reset.

    The graph is preserved — phase-level idempotency (has_working_hypothesis,
    has_investigation_summary, get_graph-aware prompts) means phases that
    already completed before the halt will be skipped, and the pivot-drain
    loop will continue from the current node set."""
    with gs.conn() as c:
        row = c.execute(
            "SELECT seed_type, seed_value FROM investigations WHERE id=?",
            (inv_id,),
        ).fetchone()
    if not row:
        return
    # Clear the halt markers before retrying so the pre-spawn quota gate
    # doesn't immediately bounce us back.
    gs.set_quota_reset_at(inv_id, None)
    gs.clear_quota_state()
    gs.set_status(inv_id, "running")
    _log(inv_id, "agent_resume", {"seed_type": row["seed_type"],
                                  "seed_value": row["seed_value"], "model": model})
    await run_investigation(inv_id, row["seed_type"], row["seed_value"], model=model)


# ── Pivot-specific system prompt ──────────────────────────────────────────
# Used by run_pivot() when the user clicks "Pivot here" on an existing node.
# Goal: extend the graph AND update the existing report node in place (never
# create a second report node).
_PIVOT_SYSTEM_PROMPT = """You are Bounce-CTI, EXTENDING an existing investigation graph via a user-initiated pivot.
The graph already contains nodes, edges, and (usually) a single report node with
value="investigation_summary". Your job is to enrich the graph from the new pivot
seed AND fold any new findings back into that existing report — NOT to create a
second one.

ABSOLUTE RULES for pivot runs:
P1. Call get_report() FIRST to get the existing report metadata. Then call
    get_graph(compact=True) for the node inventory. Use get_node(type, value)
    for full metadata of specific nodes. You will MERGE into the report, not
    replace it.
P2. Run the relevant enrichment tools for the pivot seed (the user prompt lists
    them). Follow the normal rules R1-R11 from the main system prompt: graph
    every finding, call defuse before pivoting on IPs, use correct sources,
    respect R11 (evidence-based threat_assessment — no speculation).
P3. REPORT UPDATE (MANDATORY, exactly one call):
    Re-add_node(report, "investigation_summary", metadata={...}, source="agent",
    tags=["report"]) using the CANONICAL value "investigation_summary". Because
    add_node upserts on (inv, type, value), this UPDATES the existing report in
    place.
    In the metadata you submit:
      - "summary": rewrite it to reflect the COMBINED view (original seed + pivot).
        Keep it factual, 2-4 sentences. No speculation. Obey R11.
      - "key_findings": APPEND new findings from the pivot. Do not drop prior
        findings — re-include them from the existing report.metadata.key_findings
        (you just read it via get_report()). Each finding stays {text, sources[]}.
      - "threat_assessment": start from the existing value. Only ESCALATE if a
        new direct-evidence condition from R11 is now met (cite the source+value
        in key_findings). Never escalate from domain-name semantics, age, hosting,
        or absence of hits. If no new evidence, keep the existing assessment.
      - "discriminating_markers", "pivot_suggestions", "ioc_list", "sources_used":
        union of old + new values; de-duplicate.
      - Add a "pivot_history" list entry: {"pivot_seed_type": "<type>",
        "pivot_seed_value": "<value>", "timestamp": "<iso8601 or best effort>"}.
        Extend the existing pivot_history if present, otherwise create it.
P4. Do NOT create any other report node. Do NOT use any value other than
    "investigation_summary" for the report.
P5. After the report update, stop. Do not chain further pivots.
"""


# ── Add-seed (peer seed) prompt ───────────────────────────────────────────
# Used when the analyst adds an independent IOC to an existing investigation.
# Unlike a "pivot here" (which frames the new IOC as a descendant of an
# existing graph node), add-seed treats the new IOC as a PEER — it is not
# known to be linked to the existing graph, and we forbid the agent from
# inventing an edge between the new seed and prior seeds without a concrete
# shared attribute.
_ADD_SEED_SYSTEM_PROMPT = """You are Bounce-CTI, adding a NEW PEER SEED to an existing multi-seed investigation.

This is NOT a pivot from a graph node — it is a fresh IOC the analyst wants investigated
alongside what is already on the graph. Treat it as a peer of the existing seed(s), not a
descendant.

ABSOLUTE RULES for add-seed runs:
A1. Call get_report() FIRST for existing report metadata, then
    get_graph(compact=True) for the node inventory. Note every existing node (IPs,
    NS, JARMs, certs, ASNs, registrars, hashes) and the existing seeds (nodes
    tagged "seed"). Use get_node(type, value) for full metadata on specific nodes.
    You will compare the new seed's infrastructure against these.
A2. add_node(<seed_type>, <seed_value>, tags=["seed"]) for the new seed. Then run the
    FULL single-seed workflow for it (defuse, RDAP/DNS, VT, threatfox, OTX, urlhaus,
    JARM pivot, …). Do NOT shortcut because "the graph already has stuff" — the new
    seed needs its own full enrichment. Every shared IP/NS/JARM/cert/ASN/hash you add
    is upserted on (inv, type, value) so it automatically becomes a cross-seed link
    when it already exists.
A3. FORBIDDEN: do NOT add any edge BETWEEN the new seed and any PRIOR seed unless a
    concrete, specific shared attribute justifies a specific relation. Valid examples:
      • Both use the exact same NS set → add_edge(seed_new → seed_old, same_ns_set)
      • Both share a cert fingerprint → add_edge(seed_new → seed_old, same_cert)
      • Both share an authoritative RDAP registrant email/org → same_registrant
      • Both resolve to the same IP → the ip node connects them; you MAY also add
        add_edge(seed_new → seed_old, co_resolves, evidence="shared IP <x>")
    DO NOT invent relations like "pivot_from", "part_of_batch", "co_investigated",
    "analyst_link", "related_to". If no concrete shared attribute exists, the two
    seeds stay unconnected — the graph then correctly shows independent clusters.
A4. REPORT UPDATE (exactly one add_node call, at the end). Re-call
    add_node(report, "investigation_summary", metadata={...}, source="agent",
    tags=["report"]) using the MULTI-SEED schema below. add_node upserts on
    (inv,type,value), so this UPDATES the existing report in place.
A5. Respect R1-R11 from the main system prompt (graph every finding, defuse before
    pivoting IPs, evidence-based threat_assessment only). Do NOT chain further
    pivots. Stop after the report update.

MULTI-SEED REPORT METADATA SCHEMA:
  {
    "seeds": [{"type": "...", "value": "..."}, ...],    # ALL current seeds
    "threat_assessment": "<worst of the per-seed values, always evidence-based>",
    "summary": "<3-5 sentence overview of the WHOLE investigation: list the seeds,
                 state whether they share infrastructure, overall conclusion>",
    "per_seed_summaries": {
      "<seed_value_1>": {
        "type": "<domain|ip|hash|url>",
        "summary": "<2-3 sentence overview for THIS seed, factual only>",
        "threat_assessment": "<benign|suspicious|likely_malicious|malicious>",
        "key_findings": [{"text": "...", "sources": [...]}, ...],
        "sources_used": ["dns", "rdap", ...]
      },
      "<seed_value_2>": {...}
    },
    "cross_seed_findings": [
      {"text": "<concrete shared attribute + which seeds>",
       "seeds": ["a.com", "b.com"],
       "sources": ["rdap", "dns", ...]}
    ],  # empty list [] IS a valid finding — means no shared infrastructure was found
    "key_findings": [...],             # union of per-seed findings (kept for compat)
    "discriminating_markers": [...],   # union, strings
    "pivot_suggestions": [...],        # strings
    "ioc_list": ["<exact node value>", ...],   # PLAIN STRINGS, NEVER objects
    "sources_used": [...],
    "pivot_history": [...]             # append an entry for this add-seed
  }

MIGRATION: If the existing report does NOT yet have `per_seed_summaries`, migrate it:
  - Move the existing top-level `summary`, `threat_assessment`, `key_findings`,
    `sources_used` under per_seed_summaries[<existing_primary_seed_value>] (use the
    first seed you see in the graph, tagged "seed", whose value equals the
    investigation's original seed).
  - Then add per_seed_summaries[<new_seed_value>] for the IOC you just investigated.
  - Compute the top-level summary / threat_assessment / unions from the per-seed
    entries PLUS cross_seed_findings.

Append this entry to pivot_history:
  {"kind": "add_seed", "seed_type": "<t>", "seed_value": "<v>", "timestamp": "<iso8601>"}

IMPORTANT:
- `ioc_list` items MUST be plain strings (e.g. "1.2.3.4"), NEVER objects.
- If no shared attribute is found, cross_seed_findings is [] and the overall summary
  explicitly states "the seeds do not share any observed infrastructure".
- Top-level threat_assessment = the most severe of the per-seed values. Never
  escalate from domain-name semantics, age, hosting, or absence of hits. Obey R11.
"""


async def run_add_seed(inv_id: str, seed_type: str, seed_value: str, model: str = "opus"):
    """Add a new PEER seed to an existing investigation.

    Runs the full single-seed workflow for the new IOC on the existing graph.
    Because add_node upserts on (inv, type, value), any shared infrastructure
    (IPs, NS, certs, JARMs, ASNs, registrars, hashes) automatically becomes a
    cross-seed link without the agent inventing edges. The agent then updates
    the report in place with per-seed summaries and explicit cross-seed
    findings (or an empty list, if nothing is shared).
    """
    user_prompt = (
        f"Add new PEER seed: type={seed_type} value={seed_value}\n"
        f"Investigation id: {inv_id}\n\n"
        "STEP 1: Call get_report() for the current report metadata, then get_graph(compact=True)\n"
        "        for the node inventory. Note existing seeds (tagged 'seed'), existing\n"
        "        infrastructure, and the report metadata. You will merge into that report.\n\n"
        f"STEP 2: add_node({seed_type}, {seed_value}, tags=[\"seed\"]) for the new seed.\n"
        "        Then run the full single-seed workflow — do NOT skip tools because some\n"
        "        infra seems to overlap. Each shared attribute you add is upserted, so\n"
        "        overlap automatically becomes a cross-seed link.\n\n"
    )
    if seed_type == "ip":
        user_prompt += (
            "Required tools for the new seed (each called on THIS seed value):\n"
            f"  - defuse(ip, {seed_value})\n"
            f"  - rdap_ip({seed_value})\n"
            f"  - virustotal_ip({seed_value})\n"
            f"  - shodan_host({seed_value})  (passive — JARM, banners)\n"
            f"  - onyphe_ip({seed_value})  (passive — banners, technologies)\n"
            f"  - reverse_dns({seed_value})\n"
            f"  - virustotal_resolutions_ip({seed_value})\n"
            f"  - virustotal_communicating_files(\"ip\", {seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_ip({seed_value})\n"
            "  - If a non-CDN JARM is found: shodan_search(\"ssl.jarm:<jarm>\")\n"
        )
    elif seed_type == "domain":
        user_prompt += (
            "Required tools for the new seed (each called on THIS seed value):\n"
            f"  - rdap_domain({seed_value}) / dns_resolve({seed_value})\n"
            f"  - crtsh_subdomains({seed_value})\n"
            f"  - virustotal_domain({seed_value})\n"
            f"  - virustotal_resolutions_domain({seed_value})\n"
            f"  - virustotal_communicating_files(\"domain\", {seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_domain({seed_value})\n"
            f"  - urlhaus_host({seed_value})\n"
            f"  - onyphe_domain({seed_value})  (passive fingerprinting)\n"
        )
    elif seed_type == "hash":
        user_prompt += (
            "Required tools for the new seed (each called on THIS seed value):\n"
            f"  - malwarebazaar_hash({seed_value})\n"
            f"  - virustotal_file({seed_value})\n"
            f"  - otx_file({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "For the hash node set metadata.file_name (required for UI labels).\n"
        )
    elif seed_type == "executable_name":
        user_prompt += (
            "This is a filename-only add-seed (no binary, no hash). Required:\n"
            f"  - malwarebazaar_filename({seed_value})  — top samples → graph each\n"
            "    as a hash node with an `observed_as` edge to the executable_name.\n"
            "    Top 3 samples: also virustotal_file + otx_file + malwarebazaar_hash\n"
            "    to pull family / C2 / file_name set.\n"
            f"  - threatfox_search({seed_value})\n"
            "If any returned sample's sha256 / family / C2 ALREADY exists on the\n"
            "graph (from a prior seed), that's a concrete cross-seed link — record\n"
            "it in cross_seed_findings.\n"
        )
    elif seed_type == "url":
        user_prompt += (
            "This is a URL add-seed. Graph the URL as a url node with tags=['seed'],\n"
            "derive the host, graph it as domain/ip, then run the full host workflow\n"
            "(rdap, dns, VT, threatfox, otx, urlhaus, urlscan, JARM).\n"
        )
    elif seed_type == "jarm":
        user_prompt += (
            "This is a JARM fingerprint add-seed. Required tools:\n"
            f"  - shodan_search(\"ssl.jarm:{seed_value}\")  — enumerate cluster\n"
            f"  - urlscan_search(\"hash:{seed_value}\")  — cross-source confirmation\n"
            f"  - threatfox_search({seed_value})\n"
            "  - For top 3 diverse IPs: defuse + rdap_ip + virustotal_ip + threatfox_search\n"
            "For every host with this JARM: add_node(ip) + add_edge(ip→jarm, has_jarm).\n"
            "If a cluster IP ALREADY exists on the graph (same id as a prior seed's infra),\n"
            "that's a concrete cross-seed link — record it in cross_seed_findings.\n"
        )
    elif seed_type == "asn":
        asn_num = seed_value.upper().removeprefix("AS") or seed_value
        user_prompt += (
            "This is an ASN add-seed. Required tools:\n"
            f"  - shodan_search(\"asn:AS{asn_num} port:443\")\n"
            f"  - For top 5 interesting IPs: defuse + virustotal_ip + threatfox_search + otx_ip\n"
            f"  - rdap_ip on ONE representative IP (netname/country/abuse_email)\n"
            f"  - threatfox_search(\"AS{asn_num}\")\n"
            "If multiple hosts in the AS share a JARM, graph that JARM and link all hits.\n"
            "If any cluster IP is ALREADY on the graph, record it in cross_seed_findings.\n"
        )
    elif seed_type == "email":
        user_prompt += (
            "This is an email add-seed. Required tools:\n"
            f"  - emailrep_check({seed_value})\n"
            f"  - whoxy_reverse(email=\"{seed_value}\")  — every reverse-WHOIS domain hit\n"
            "    becomes a domain node + registered edge from the email.\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "If any returned domain ALREADY exists on the graph, that's a concrete\n"
            "cross-seed link — record it in cross_seed_findings.\n"
        )
    elif seed_type == "wallet_address":
        user_prompt += (
            "This is a wallet_address add-seed. Required tools:\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")  — phishing page DOM may include it\n"
            "Set metadata.chain on the wallet node (btc / eth / xmr / …).\n"
        )
    elif seed_type == "username":
        user_prompt += (
            "This is a username add-seed. Required tools:\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")\n"
            "Every domain / IP / hash co-mentioned with the handle becomes a node\n"
            "with a uses_handle edge to the username.\n"
        )

    user_prompt += (
        "\nSTEP 3: CROSS-SEED CHECK. For each infrastructure node you added during STEP 2,\n"
        "check whether it was ALREADY in the graph before this run (same id → same value\n"
        "as a prior seed's infra). When that happens, this seed concretely shares that\n"
        "attribute with a prior seed. Collect those into cross_seed_findings, citing the\n"
        "attribute + which seeds share it + which source reported it.\n"
        "If nothing is shared, cross_seed_findings stays [] (which is itself a valid\n"
        "finding and must be stated in the top-level summary).\n"
        "\nSTEP 4: UPDATE THE REPORT (exactly one add_node call, at the end).\n"
        "add_node(report, \"investigation_summary\", metadata={MULTI_SEED_SCHEMA},\n"
        "        source=\"agent\", tags=[\"report\"]).\n"
        "Remember to migrate flat fields from the existing report into\n"
        "per_seed_summaries[<primary_seed_value>] if that structure is not yet there.\n"
        f"Then add per_seed_summaries[\"{seed_value}\"] for this new seed.\n"
        "Append to pivot_history: {\"kind\": \"add_seed\", \"seed_type\":\"" + seed_type +
        f"\", \"seed_value\":\"{seed_value}\", \"timestamp\":\"<iso8601>\"}}.\n"
        "Then STOP."
    )

    env = _build_env(inv_id)
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"cwd": str(ROOT), "mcp_config": str(mcp_cfg_path),
                                    "phase": "add_seed",
                                    "seed_type": seed_type, "seed_value": seed_value})

    blocked, reset_at, msg = quota_block_active()
    if blocked:
        _log(inv_id, "agent_skipped_quota", {"reset_at": reset_at, "message": msg,
                                             "phase": "add_seed"})
        _finalise_quota_halt(inv_id, {"reset_at": reset_at, "message": msg})
        return

    rc, saw_result, has_report, quota = await _run_claude_phase(
        inv_id, user_prompt, _ADD_SEED_SYSTEM_PROMPT, model, env, mcp_cfg_path,
        phase="add_seed", max_turns=80,
    )

    if quota["hit"]:
        _finalise_quota_halt(inv_id, quota)
        return

    final_status = "done" if (saw_result or rc == 0) else f"error rc={rc}"
    gs.set_status(inv_id, final_status)
    _log(inv_id, "agent_exit", {"rc": rc, "status": final_status, "phase": "add_seed",
                                "has_report": has_report,
                                "seed_type": seed_type, "seed_value": seed_value})


async def run_pivot(inv_id: str, seed_type: str, seed_value: str, model: str = "opus"):
    """Extend an existing investigation graph with a new pivot seed.

    Uses a pivot-specific prompt that tells the agent to update the existing
    report node (singleton with value="investigation_summary") in place rather
    than create a duplicate. The investigation's status is flipped to "running"
    by the API endpoint, and this function emits agent_exit on completion so
    the frontend sidebar refreshes live.
    """
    user_prompt = (
        f"Pivot seed: type={seed_type} value={seed_value}\n"
        f"Investigation id: {inv_id}\n\n"
        "STEP 1: Call get_report() for the current report metadata, then\n"
        "        get_graph(compact=True) for the node inventory.\n"
        "        You will merge into the existing report.\n\n"
        "STEP 2: Run pivot enrichment for this seed. "
    )
    if seed_type == "ip":
        user_prompt += (
            "Call these tools (skip any whose results are already in the graph):\n"
            f"  - rdap_ip({seed_value})\n"
            f"  - virustotal_ip({seed_value})\n"
            f"  - shodan_host({seed_value})  (passive — extract JARM, banners, technologies)\n"
            f"  - onyphe_ip({seed_value})  (passive — banners, cert, technologies)\n"
            f"  - reverse_dns({seed_value})\n"
            f"  - virustotal_resolutions_ip({seed_value})\n"
            f"  - virustotal_communicating_files(\"ip\", {seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_ip({seed_value})\n"
            "If a JARM is extracted and it is not a well-known CDN JARM, also call\n"
            f"  - shodan_search(\"ssl.jarm:<jarm>\") and add new IPs with same_jarm edges.\n"
        )
    elif seed_type == "domain":
        user_prompt += (
            "Call these tools (skip any whose results are already in the graph):\n"
            f"  - rdap_domain({seed_value}) / dns_resolve({seed_value})\n"
            f"  - crtsh_subdomains({seed_value})\n"
            f"  - virustotal_domain({seed_value})\n"
            f"  - virustotal_resolutions_domain({seed_value})\n"
            f"  - virustotal_communicating_files(\"domain\", {seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - otx_domain({seed_value})\n"
            f"  - onyphe_domain({seed_value})  (passive fingerprinting)\n"
        )
    elif seed_type == "hash":
        user_prompt += (
            "Call these tools (skip any whose results are already in the graph):\n"
            f"  - malwarebazaar_hash({seed_value})\n"
            f"  - virustotal_file({seed_value})\n"
            f"  - otx_file({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "For every hash node created or updated, set metadata.file_name.\n"
        )
    elif seed_type == "executable_name":
        user_prompt += (
            "This is a filename-only pivot (no binary, no hash). Required:\n"
            f"  - malwarebazaar_filename({seed_value})  — graph each returned\n"
            "    sample's sha256 as a hash node + observed_as edge to the\n"
            "    executable_name. Top 3 samples: also virustotal_file +\n"
            "    malwarebazaar_hash + otx_file to pull family + C2.\n"
            f"  - threatfox_search({seed_value})\n"
        )
    elif seed_type == "url":
        user_prompt += (
            "This is a URL pivot. Graph the URL as a url node (tag as seed if new),\n"
            "extract the host and graph it as domain/ip node. Then run enrichment on\n"
            "the host as you would for a domain/ip pivot:\n"
            f"  - urlscan_search(\"page.url:{seed_value}\")\n"
            f"  - urlhaus_host(<host>)\n"
            "  - rdap + DNS + VT (domain or ip flavor, depending on host)\n"
            "  - threatfox_search on both the URL and the host\n"
        )
    elif seed_type == "jarm":
        user_prompt += (
            "This is a JARM pivot. Call these tools (skip any already in graph):\n"
            f"  - shodan_search(\"ssl.jarm:{seed_value}\")  — find cluster hosts\n"
            f"  - urlscan_search(\"hash:{seed_value}\")\n"
            f"  - threatfox_search({seed_value})\n"
            "For each new IP with this JARM: add_node(ip) + add_edge(ip→jarm, has_jarm).\n"
            "For top 3 IPs: defuse + virustotal_ip + threatfox_search.\n"
        )
    elif seed_type == "asn":
        asn_num = seed_value.upper().removeprefix("AS") or seed_value
        user_prompt += (
            "This is an ASN pivot. Call these tools (skip any already in graph):\n"
            f"  - shodan_search(\"asn:AS{asn_num} port:443\")\n"
            f"  - rdap_ip on one representative IP for netname/country/abuse_email\n"
            f"  - threatfox_search(\"AS{asn_num}\")\n"
            "For top 5 interesting IPs in the AS: defuse + virustotal_ip + threatfox_search.\n"
            "Tag the asn 'abused_asn' when ≥2 of those hosts return detection hits.\n"
        )
    elif seed_type == "email":
        user_prompt += (
            "This is an email pivot. Call these tools (skip any already in graph):\n"
            f"  - emailrep_check({seed_value})\n"
            f"  - whoxy_reverse(email=\"{seed_value}\")\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - threatfox_search({seed_value})\n"
            "For each new domain returned by whoxy: add_node + registered edge.\n"
        )
    elif seed_type == "wallet_address":
        user_prompt += (
            "This is a wallet_address pivot. Call these tools (skip already-graphed):\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")\n"
        )
    elif seed_type == "username":
        user_prompt += (
            "This is a username pivot. Call these tools (skip already-graphed):\n"
            f"  - threatfox_search({seed_value})\n"
            f"  - pulsedive_indicator({seed_value})\n"
            f"  - opencti_lookup_indicator({seed_value})\n"
            f"  - urlscan_search(\"{seed_value}\")\n"
        )
    user_prompt += (
        "\nSTEP 3: UPDATE THE REPORT (do this exactly once, at the end).\n"
        "Re-call add_node(report, \"investigation_summary\", metadata={...},\n"
        "source=\"agent\", tags=[\"report\"]) with MERGED metadata as described in\n"
        "P3 of the system prompt. Preserve prior key_findings; append new ones.\n"
        "Only escalate threat_assessment if a new direct-evidence R11 condition\n"
        "is met (cite the source in key_findings).\n"
        "Then STOP."
    )

    env = _build_env(inv_id)
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"cwd": str(ROOT), "mcp_config": str(mcp_cfg_path), "phase": "pivot",
                                    "pivot_seed_type": seed_type, "pivot_seed_value": seed_value})

    blocked, reset_at, msg = quota_block_active()
    if blocked:
        _log(inv_id, "agent_skipped_quota", {"reset_at": reset_at, "message": msg,
                                             "phase": "pivot"})
        _finalise_quota_halt(inv_id, {"reset_at": reset_at, "message": msg})
        return

    rc, saw_result, has_report, quota = await _run_claude_phase(
        inv_id, user_prompt, _PIVOT_SYSTEM_PROMPT, model, env, mcp_cfg_path,
        phase="pivot", max_turns=40
    )

    if quota["hit"]:
        _finalise_quota_halt(inv_id, quota)
        return

    # Final status — pivot is considered successful as long as the agent ran
    # (saw_result or rc==0). A pivot does not necessarily add a brand-new report;
    # it updates the existing one.
    final_status = "done" if (saw_result or rc == 0) else f"error rc={rc}"
    gs.set_status(inv_id, final_status)
    _log(inv_id, "agent_exit", {"rc": rc, "status": final_status, "phase": "pivot",
                                "has_report": has_report})


# ── Custom prompt system prompt ──────────────────────────────────────────
_CUSTOM_PROMPT_SYSTEM_PROMPT = """You are Bounce-CTI, executing a CUSTOM ANALYST PROMPT on an existing investigation graph.
The graph already contains nodes, edges, and (usually) a single report node with
value="investigation_summary". The analyst has typed a free-form instruction.

ABSOLUTE RULES for custom prompt runs:
C1. Read the existing graph and report. Use get_report() to get the current report
    metadata (summary, threat_assessment, prompt_history, etc.). For the node
    inventory, use get_graph(compact=True) which returns a lightweight summary
    without metadata. Use get_node(type, value) if you need full metadata for
    specific nodes. NEVER call get_graph() without compact=True on large
    investigations — it will exceed output limits and fail.
C2. Follow the analyst's instruction. You have full access to all CTI tools. Use
    them as needed to fulfil the request. Follow rules R1-R11 from the main system
    prompt: graph every finding, call defuse before pivoting on IPs, use correct
    sources, respect R11 (evidence-based threat_assessment — no speculation).
C3. REPORT UPDATE (MANDATORY, exactly one call, at the end):
    Re-add_node(report, "investigation_summary", metadata={...}, source="agent",
    tags=["report"]) using the CANONICAL value "investigation_summary". Because
    add_node upserts on (inv, type, value), this UPDATES the existing report in
    place.
    In the metadata you submit:
      - Preserve ALL existing fields from the current report metadata.
      - Update "summary" to incorporate the new findings from this prompt run.
      - APPEND new key_findings. Do not drop prior findings.
      - Only ESCALATE threat_assessment if new direct-evidence conditions are met.
      - CRITICAL — "prompt_history": append an entry with this EXACT schema:
        {
          "prompt": "<the analyst's instruction, verbatim>",
          "response": "<your direct answer to the analyst — 2-6 sentences,
                        factual, referencing specific IOCs and tool results.
                        This is shown directly to the analyst as THE answer to
                        their question. Be specific and useful, not generic.>",
          "nodes_added": <integer — how many new nodes you added to the graph>,
          "nodes_updated": <integer — how many existing nodes you updated>,
          "selected_nodes": ["<value1>", "<value2>", ...] or null,
          "timestamp": "<iso8601>"
        }
        Extend existing prompt_history if present, otherwise create it as a list.
        The "response" field is the MOST IMPORTANT part — it is what the analyst
        sees. Make it a direct, actionable answer. Examples:
          GOOD: "Found 3 additional IPs (1.2.3.4, 5.6.7.8, 9.10.11.12) sharing
                 the same JARM fingerprint. Two of them (1.2.3.4, 5.6.7.8) have
                 VirusTotal detections, confirming malicious infrastructure."
          BAD:  "I have investigated the selected nodes and updated the report."
C4. Do NOT create any other report node. Do NOT use any value other than
    "investigation_summary" for the report.
C5. After the report update, stop. Do not chain further actions beyond what was asked.
"""


async def run_custom_prompt(inv_id: str, prompt_text: str, model: str = "opus",
                            selected_nodes: list[dict] | None = None):
    """Run a custom analyst prompt on an existing investigation."""
    # Fetch existing graph to build context snapshot and conversation history.
    past_prompts: list = []
    graph_snapshot = ""
    report_meta: dict = {}
    try:
        g = gs.get_graph(inv_id)
        all_nodes = g.get("nodes", [])
        all_edges = g.get("edges", [])
        report_node = next(
            (n for n in all_nodes
             if n.get("type") == "report" and n.get("value") == "investigation_summary"),
            None
        )
        if report_node:
            report_meta = report_node.get("metadata") or {}
            ph = report_meta.get("prompt_history") or []
            past_prompts = list(ph)

        # Build compact graph snapshot so the agent understands the current state
        # without needing to call get_graph() first.
        non_report = [n for n in all_nodes if n.get("type") != "report"]
        if non_report:
            from collections import Counter
            type_counts = Counter(n.get("type", "?") for n in non_report)
            lines = [f"CURRENT GRAPH SNAPSHOT ({len(non_report)} nodes, {len(all_edges)} edges):"]
            lines.append(f"  Types: {', '.join(f'{t}:{c}' for t, c in type_counts.most_common())}")
            # List up to 60 nodes grouped by type for reference
            by_type: dict[str, list[str]] = {}
            for n in non_report:
                by_type.setdefault(n.get("type", "?"), []).append(n.get("value", ""))
            for t in sorted(by_type, key=lambda x: -type_counts[x]):
                vals = by_type[t]
                display = vals[:15]
                extra = f" (+{len(vals)-15} more)" if len(vals) > 15 else ""
                lines.append(f"  [{t}] {', '.join(display)}{extra}")
            # Current threat assessment and summary from existing report
            if report_meta.get("threat_assessment"):
                lines.append(f"  Threat assessment: {report_meta['threat_assessment']}")
            if report_meta.get("summary"):
                s = report_meta["summary"]
                lines.append(f"  Summary: {s[:300]}{'…' if len(s) > 300 else ''}")
            graph_snapshot = "\n".join(lines) + "\n\n"
    except Exception:
        pass

    user_prompt = f"Investigation id: {inv_id}\n\n"

    # Include the graph snapshot so the agent has immediate context
    if graph_snapshot:
        user_prompt += graph_snapshot

    # Include last 6 conversation turns as explicit context so the agent can
    # maintain a coherent multi-turn dialogue without having to re-derive it
    # from the raw graph each time.
    if past_prompts:
        user_prompt += "CONVERSATION HISTORY (previous analyst–agent exchanges — maintain context):\n"
        for entry in past_prompts[-6:]:
            q = (entry.get("prompt") or "").strip()
            a = (entry.get("response") or "").strip()
            if q:
                user_prompt += f"  ANALYST: {q}\n"
            if a:
                user_prompt += f"  AGENT: {a}\n"
            user_prompt += "\n"
        user_prompt += "---\n\n"

    if selected_nodes:
        user_prompt += (
            "SELECTED NODES — the analyst has highlighted these specific nodes on the graph.\n"
            "Your instructions below apply PRIMARILY to these nodes, but you still have\n"
            "access to the full graph for context.\n"
        )
        for i, n in enumerate(selected_nodes, 1):
            user_prompt += f"  {i}. [{n['type']}] {n['value']}\n"
        user_prompt += "\n"

    user_prompt += (
        f"ANALYST INSTRUCTION:\n{prompt_text}\n\n"
        "STEP 1: Call get_report() to get the current report metadata (including prompt_history "
        "you must preserve). Then call get_graph(compact=True) for the node inventory. "
        "Use get_node(type, value) for specific nodes if you need full metadata.\n"
    )

    if selected_nodes:
        user_prompt += (
            "STEP 2: Focus on the SELECTED NODES listed above. Execute the analyst's\n"
            "instruction using available CTI tools, applying it to those nodes specifically.\n"
            "You may also use the rest of the graph for context and cross-referencing.\n"
        )
    else:
        user_prompt += (
            "STEP 2: Execute the analyst's instruction above using available CTI tools.\n"
        )

    user_prompt += (
        "STEP 3: UPDATE THE REPORT (exactly one add_node call, at the end).\n"
        "Re-call add_node(report, \"investigation_summary\", metadata={...},\n"
        "source=\"agent\", tags=[\"report\"]) with MERGED metadata as described in\n"
        "C3 of the system prompt. Preserve prior key_findings; append new ones.\n"
        "Then STOP."
    )

    env = _build_env(inv_id)
    mcp_cfg_path = _write_mcp_config(inv_id)
    _log(inv_id, "agent_starting", {"cwd": str(ROOT), "mcp_config": str(mcp_cfg_path),
                                    "phase": "custom_prompt",
                                    "prompt_preview": prompt_text[:200]})

    blocked, reset_at, msg = quota_block_active()
    if blocked:
        _log(inv_id, "agent_skipped_quota", {"reset_at": reset_at, "message": msg,
                                             "phase": "custom_prompt"})
        _finalise_quota_halt(inv_id, {"reset_at": reset_at, "message": msg})
        return

    rc, saw_result, has_report, quota = await _run_claude_phase(
        inv_id, user_prompt, _CUSTOM_PROMPT_SYSTEM_PROMPT, model, env, mcp_cfg_path,
        phase="custom_prompt", max_turns=60,
    )

    if quota["hit"]:
        _finalise_quota_halt(inv_id, quota)
        return

    final_status = "done" if (saw_result or rc == 0) else f"error rc={rc}"
    gs.set_status(inv_id, final_status)
    _log(inv_id, "agent_exit", {"rc": rc, "status": final_status, "phase": "custom_prompt",
                                "has_report": has_report})
