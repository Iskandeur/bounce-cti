"""A bare-model baseline for the eval (roadmap J4): same model, same seed, no Bounce-CTI.

EVAL_RESULTS.md could say how Bounce-CTI scores, never what it adds to the model
it runs on. This script gives each eval case to ``claude -p`` with nothing of
Bounce-CTI around it, in two arms:

- ``memory``: no tool at all (``--tools ""``). What the model already knows.
- ``web``: the CLI's own WebSearch and WebFetch, nothing else. Roughly what an
  analyst gets by pasting the seed into a chat that can search the web.

Both arms get the same short analyst brief and answer in one fixed JSON shape
(indicators, attribution, verdict). The answer becomes a graph of the shape
Bounce-CTI writes (``to_graph``) and is scored by ``eval/scorer.py`` itself
(``score_case``, ``score_negative``), so recall comes from the same code on both
sides. What is not comparable is said so in the output rather than scored:

- CAP is a process score (pivot selection through Bounce-CTI's own tools), so a
  bare model scores 0 on it by construction. Only recall-type dimensions are
  compared: NR, ER, MK, COV (= ``rq_meta.node_pct``) and the actor hit.
- Provenance is judged more strictly for the baseline than the scorer judges
  Bounce-CTI: the baseline's corpus is what the web returned, never its own
  reasoning or its own search queries (a model must not cite itself). The
  memory arm has no corpus, so every attribution it makes is untraceable. That
  is a fact about traceability, not a claim that the attribution is wrong.
- The web arm can read the public write-ups the ground truth comes from. The
  hosts it read are recorded per case, so a reader can see when it did.

Each run is isolated: an empty working directory outside any checkout (so no
CLAUDE.md is discovered), no MCP server (``--strict-mcp-config`` with an empty
config), no session persisted, skills disabled, and a filtered environment.
Authentication is the CLI's own (``~/.claude``); this script never reads it.

Usage:
    python3 eval/baseline.py run --arm memory --model claude-opus-5 \\
        --out eval/baseline/<date> 2 3 8 9 12 N1 N2 N3
    python3 eval/baseline.py run --arm web --model claude-opus-5 --out ... 2 3 8 9 12 N1 N2 N3
    python3 eval/baseline.py run --arm web --model claude-opus-5 --out ... \\
        --seeds <batch>/seeds.json P1 P2 ...   # a prospective batch (§4.E)
    python3 eval/baseline.py compare --out eval/baseline/<date> \\
        [--bounce <dir with c02/graph.json…, as fetch.py writes>] \\
        [--bounce-model claude-opus-5] [--date <date>] [--write]

``compare --write`` leaves ``results.json`` (scores only) and ``results.md`` in
``--out``; eval/results_digest.py publishes the latest one in EVAL_RESULTS.md.
The raw answers and streams stay out of the repo: they can quote registrant
records and other third-party personal data.

Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
# cases first: scorer puts /tmp/eval_run ahead on sys.path, where a stale copy of
# cases.py from an older run may live. Imported here, the module is cached and
# scorer gets this checkout's ground truth.
from cases import CASES, NEGATIVE_CASES  # noqa: E402
import scorer  # noqa: E402
# No fallback: a copy of cases.py without the table would silently report every
# web run as "answer key not reached". Fail loudly instead.
from cases import GT_SOURCE_HOSTS  # noqa: E402

ARMS = {"memory": "", "web": "WebSearch,WebFetch"}
FRESH_SUBSET = (2, 3, 8, 9, 12)
TIMEOUT_S = {"memory": 600, "web": 1800}
MAX_TURNS = {"memory": 2, "web": 40}

# Environment the bare run inherits: enough to find the CLI and its own login,
# nothing that would change its behaviour (effort level, nested-session flags,
# the operator's own tooling).
_ENV_KEEP = {"HOME", "PATH", "LANG", "LC_ALL", "USER", "LOGNAME", "TERM", "TZ",
             "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR"}

_TOOLS_LINE = {
    "memory": "You have no tools in this session. Answer from what you already know, "
              "and say how sure you are.",
    "web": "You can search the web and read pages (WebSearch, WebFetch). Use them as "
           "an analyst would.",
}

ANSWER_SHAPE = """{
  "verdict": "malicious" | "suspicious" | "benign" | "unknown",
  "summary": "<your analyst summary>",
  "attribution": [{"name": "...", "kind": "actor|malware|ransomware|phishing_kit|tool|framework|campaign",
                   "confidence": 0.0, "basis": "..."}],
  "indicators": [{"type": "domain|subdomain|ip|hash|url|email|asn|cert_sha1|cert_serial|cert_cn|jarm|registrar|other",
                  "value": "...", "linked_to": "<another value of this answer, or the seed>",
                  "relation": "resolves_to|contacts|drops|hosted_on|registered_by|shares_infra|related_to",
                  "malicious": true, "basis": "...", "source_url": "<page you read it on, or empty>"}]
}"""


def build_prompt(case: dict, arm: str) -> str:
    return (
        "You are a cyber threat intelligence analyst. Investigate this "
        f"{case['seed_type']}:\n\n    {case['seed_value']}\n\n"
        "Find the infrastructure related to it (domains, IP addresses, file hashes, URLs, "
        "email addresses, certificates, ASNs) and say who or what is behind it (threat "
        "actor, malware family, phishing kit, campaign) when you can support it. If it looks "
        "benign, say so: do not invent a cluster. \"attribution\" is for threats only: a "
        "legitimate owner or operator is not an attribution, name it in the summary.\n\n"
        f"{_TOOLS_LINE[arm]}\n\n"
        "When you are done, answer with ONE JSON object of this shape and nothing after it:\n"
        f"{ANSWER_SHAPE}\n"
        "List only indicators you can stand behind, and write each IOC in full in \"value\" "
        "(not defanged)."
    )


def prompt_sha(prompt: str) -> str:
    """Short fingerprint of the brief a run got: compare() flags a run whose
    brief is not the one this checkout would send."""
    return hashlib.sha1(prompt.encode("utf-8")).hexdigest()[:12]


def build_cmd(claude_bin: str, arm: str, model: str, prompt: str) -> list[str]:
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    cmd = [
        claude_bin, "-p", prompt,
        "--model", model,
        "--tools", ARMS[arm],
        "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
        "--disable-slash-commands",
        "--no-session-persistence",
        "--output-format", "stream-json", "--verbose",
        "--max-turns", str(MAX_TURNS[arm]),
    ]
    if ARMS[arm]:
        # --tools only offers a tool; in -p mode nobody is there to grant it, so
        # without this every call is denied and the arm answers from memory.
        cmd += ["--allowedTools", ARMS[arm]]
    return cmd


# The CLI's own refusal, at the start of the tool result. Matched there only: a
# fetched page that talks about "permission denied" is a page that was read.
_DENIED_RE = re.compile(r"^\s*Claude requested permissions to use \w+, but you haven't granted it")


def permission_denials(parsed: dict) -> int:
    """Tool calls the CLI refused. A web arm that was refused its tools is a
    memory arm with a different label: compare() reports it, never scores it
    as a web result."""
    return sum(1 for r in parsed["tool_results"] if _DENIED_RE.search(r["text"] or ""))


def child_env(environ: dict) -> dict:
    return {k: v for k, v in environ.items() if k in _ENV_KEEP or k.startswith("XDG_")}


def case_for(label: str, seeds: dict | None = None) -> tuple[dict, bool, str]:
    """'2' → (case 2, False, 'c02'); 'N1' → (negative 101, True, 'n01'); a label of
    ``seeds`` (a prospective batch, eval/prospective.py) → (that seed, False, label)."""
    if seeds and label in seeds:
        s = seeds[label]
        return ({"case_id": label, "name": label, "seed_type": s["seed_type"],
                 "seed_value": s["seed_value"]}, False, label)
    if label.upper().startswith("N"):
        n = int(label[1:])
        for neg in NEGATIVE_CASES:
            if neg["case_id"] - 100 == n:
                return neg, True, neg.get("dir") or f"n{n:02d}"
        raise KeyError(label)
    cid = int(label)
    for c in CASES:
        if c["case_id"] == cid:
            return c, False, f"c{cid:02d}"
    raise KeyError(label)


# ── stream parsing ─────────────────────────────────────────────────────────

def _block_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") == "text":
                    parts.append(b.get("text") or "")
                elif "content" in b:
                    parts.append(_block_text(b["content"]))
        return "\n".join(parts)
    if isinstance(content, dict):
        return json.dumps(content)
    return ""


def parse_stream(lines) -> dict:
    out = {"model": None, "cli": None, "tools": None, "tool_calls": [], "tool_results": [],
           "texts": [], "final": "", "num_turns": None, "duration_ms": None,
           "is_error": None, "result_subtype": None}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        t = e.get("type")
        if t == "system" and e.get("subtype") == "init":
            out["model"] = e.get("model")
            out["cli"] = e.get("claude_code_version")
            out["tools"] = e.get("tools")
        elif t == "assistant":
            for b in (e.get("message") or {}).get("content") or []:
                if b.get("type") == "text" and (b.get("text") or "").strip():
                    out["texts"].append(b["text"])
                elif b.get("type") == "tool_use":
                    out["tool_calls"].append({"id": b.get("id"), "name": b.get("name"),
                                              "input": b.get("input") or {}})
        elif t == "user":
            for b in (e.get("message") or {}).get("content") or []:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    out["tool_results"].append({"id": b.get("tool_use_id"),
                                                "text": _block_text(b.get("content"))})
        elif t == "result":
            out["final"] = e.get("result") or ""
            out["num_turns"] = e.get("num_turns")
            out["duration_ms"] = e.get("duration_ms")
            out["is_error"] = e.get("is_error")
            out["result_subtype"] = e.get("subtype")
    if not out["final"] and out["texts"]:
        out["final"] = out["texts"][-1]
    return out


def extract_answer(text: str) -> dict | None:
    """The answer object: the last ```json fence that parses, else the last
    balanced {...} that parses and looks like an answer."""
    if not text:
        return None
    for body in reversed(re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)):
        try:
            d = json.loads(body)
        except ValueError:
            continue
        if isinstance(d, dict):
            return d
    starts = [i for i, ch in enumerate(text) if ch == "{"]
    for s in reversed(starts):
        depth, in_str, esc = 0, False, False
        for j in range(s, len(text)):
            ch = text[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        d = json.loads(text[s:j + 1])
                    except ValueError:
                        break
                    if isinstance(d, dict) and ({"indicators", "attribution", "verdict"} & set(d)):
                        return d
                    break
    return None


# ── answer → graph (Bounce-CTI's shape) ────────────────────────────────────

_TYPE_MAP = {
    "ipv4": "ip", "ipv6": "ip", "ip_address": "ip", "fqdn": "domain", "hostname": "domain",
    "host": "domain", "sha256": "hash", "sha1": "hash", "md5": "hash", "file_hash": "hash",
    "imphash": "hash", "e-mail": "email", "email_address": "email", "certificate": "cert_sha1",
    "cert": "cert_sha1", "as": "asn",
}
_KIND_MAP = {"threat_actor": "actor", "group": "actor", "intrusion_set": "actor",
             "malware_family": "malware", "kit": "phishing_kit"}
SEED_TYPES = {"hash": "hash", "domain": "domain", "ip": "ip", "url": "url", "email": "email"}


def refang(v: str) -> str:
    v = (v or "").strip()
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("[@]", "@"),
                 ("hxxps", "https"), ("hxxp", "http")):
        v = v.replace(a, b)
    return v


def to_graph(case: dict, answer: dict | None) -> dict:
    """The answer as nodes and edges of the shape scorer.py reads. The seed node
    is always there, as Bounce-CTI always graphs its seed. What the model says
    about its sources is kept as ``claimed_*`` metadata, never under the keys
    scorer._has_provenance accepts (evidence, source, …): a citation the model
    wrote is not provenance."""
    answer = answer or {}
    nodes: list[dict] = []
    edges: list[dict] = []
    by_value: dict[str, str] = {}

    def add(ntype: str, value: str, tags=(), metadata=None) -> str:
        key = value.lower()
        if key in by_value:
            nid = by_value[key]
            node = next(n for n in nodes if n["id"] == nid)
            node["tags"] = sorted(set(node["tags"]) | set(tags))
            return nid
        nid = f"n{len(nodes)}"
        nodes.append({"id": nid, "type": ntype, "value": value, "tags": sorted(set(tags)),
                      "metadata": metadata or {}})
        by_value[key] = nid
        return nid

    seed = case["seed_value"]
    seed_id = add(SEED_TYPES.get(case["seed_type"], case["seed_type"]), seed, ("seed",))
    for ind in answer.get("indicators") or []:
        if not isinstance(ind, dict):
            continue
        value = refang(str(ind.get("value") or ""))
        if not value:
            continue
        itype = str(ind.get("type") or "other").lower().strip()
        itype = _TYPE_MAP.get(itype, itype)
        tags = ("malicious",) if ind.get("malicious") is True else ()
        nid = add(itype, value, tags, {
            "claimed_basis": ind.get("basis") or "",
            "claimed_source_url": ind.get("source_url") or "",
            "relation": ind.get("relation") or "",
        })
        link = refang(str(ind.get("linked_to") or ""))
        src = by_value.get(link.lower(), seed_id) if link else seed_id
        if src != nid:
            edges.append({"src": src, "dst": nid, "relation": ind.get("relation") or "related_to"})
    for att in answer.get("attribution") or []:
        if not isinstance(att, dict) or not str(att.get("name") or "").strip():
            continue
        kind = str(att.get("kind") or "actor").lower().strip()
        kind = _KIND_MAP.get(kind, kind)
        nid = add(kind, str(att["name"]).strip(), (), {
            "claimed_basis": att.get("basis") or "", "confidence": att.get("confidence")})
        edges.append({"src": seed_id, "dst": nid, "relation": "attributed_to"})
    report_md = {
        "summary": str(answer.get("summary") or ""),
        "verdict": str(answer.get("verdict") or ""),
        "indicators": " ".join(n["value"] for n in nodes),
        "attribution": " ".join(str(a.get("name") or "") for a in answer.get("attribution") or []
                                if isinstance(a, dict)),
    }
    nodes.append({"id": f"n{len(nodes)}", "type": "report", "value": "investigation_summary",
                  "tags": [], "metadata": report_md})
    return {"nodes": nodes, "edges": edges}


def to_transcript(parsed: dict) -> dict:
    """Tool calls and what they returned, in the transcript shape scorer.py
    reads. Deliberately left out of the corpus the scorer searches: the model's
    own text and its tool inputs (a search query naming an actor would
    otherwise make that attribution 'traceable')."""
    entries = []
    names = {c["id"]: c["name"] for c in parsed["tool_calls"]}
    for c in parsed["tool_calls"]:
        entries.append({"kind": "tool", "name": c["name"], "query": c["input"]})
    for r in parsed["tool_results"]:
        entries.append({"kind": "tool_result", "name": names.get(r["id"], "?"),
                        "result_preview": r["text"]})
    return {"entries": entries}


def hosts_read(parsed: dict) -> list[str]:
    """Hosts of the pages actually fetched (a refused fetch read nothing)."""
    denied = {r["id"] for r in parsed["tool_results"] if _DENIED_RE.search(r["text"] or "")}
    hosts = set()
    for c in parsed["tool_calls"]:
        url = (c.get("input") or {}).get("url")
        if url and c.get("id") not in denied:
            hosts.add(urlparse(url).hostname or url)
    return sorted(h for h in hosts if h)


_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+")


def hosts_seen(parsed: dict) -> list[str]:
    """Hosts linked from what WebSearch returned. A search result's snippet can
    already carry the write-up's content, page fetched or not."""
    search_ids = {c["id"] for c in parsed["tool_calls"] if c.get("name") == "WebSearch"}
    hosts = set()
    for r in parsed["tool_results"]:
        if r["id"] in search_ids and not _DENIED_RE.search(r["text"] or ""):
            for url in _URL_RE.findall(r["text"] or ""):
                h = urlparse(url).hostname
                if h:
                    hosts.add(h)
    return sorted(hosts)


def _on(host: str, sources: list[str]) -> bool:
    return any(host == s or host.endswith("." + s) for s in sources)


def answer_key(case_id: int, read: list[str], seen: list[str]) -> str | None:
    """Did the web arm reach the write-up its ground truth comes from?
    'fetched', 'in search results', 'not reached', or None when the case's
    source is not known (cases.GT_SOURCE_HOSTS)."""
    sources = GT_SOURCE_HOSTS.get(case_id)
    if not sources:
        return None
    if any(_on(h, sources) for h in read):
        return "fetched"
    if any(_on(h, sources) for h in seen):
        return "in search results"
    return "not reached"


# ── running ────────────────────────────────────────────────────────────────

def load_seeds(path: Path) -> dict:
    """A prospective batch's seeds.json, by label. Its graphs land in
    <out>/<arm>/<label>/, the arm directory eval/prospective.py seals."""
    seeds = {}
    for s in json.loads(path.read_text(encoding="utf-8")):
        if not (s.get("label") and s.get("seed_type") and s.get("seed_value")):
            raise ValueError(f"{path}: every seed needs label, seed_type and seed_value")
        seeds[s["label"]] = s
    return seeds


def run_case(label: str, arm: str, model: str, out: Path, claude_bin: str,
             seeds: dict | None = None) -> dict:
    case, negative, dname = case_for(label, seeds)
    d = out / arm / dname
    d.mkdir(parents=True, exist_ok=True)
    prompt = build_prompt(case, arm)
    cmd = build_cmd(claude_bin, arm, model, prompt)
    started = time.time()
    timed_out = False
    with tempfile.TemporaryDirectory(prefix="bounce-baseline-") as cwd, \
            open(d / "stream.jsonl", "w", encoding="utf-8") as f:
        proc = subprocess.Popen(cmd, cwd=cwd, env=child_env(os.environ), stdout=f,
                                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True)
        try:
            _, stderr = proc.communicate(timeout=TIMEOUT_S[arm])
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            _, stderr = proc.communicate()
    parsed = parse_stream((d / "stream.jsonl").read_text(encoding="utf-8").splitlines())
    answer = extract_answer(parsed["final"])
    graph = to_graph(case, answer)
    (d / "answer.json").write_text(json.dumps(answer, indent=2), encoding="utf-8")
    (d / "graph.json").write_text(json.dumps(graph), encoding="utf-8")
    (d / "transcript.json").write_text(json.dumps(to_transcript(parsed)), encoding="utf-8")
    meta = {
        "case": label, "arm": arm, "model_requested": model, "model": parsed["model"],
        "prompt_sha": prompt_sha(prompt),
        "cli": parsed["cli"], "tools_offered": parsed["tools"], "rc": proc.returncode,
        "timed_out": timed_out, "wall_s": round(time.time() - started, 1),
        "num_turns": parsed["num_turns"], "result_subtype": parsed["result_subtype"],
        "is_error": parsed["is_error"], "answer_parsed": answer is not None,
        "tool_calls": [c["name"] for c in parsed["tool_calls"]], "hosts_read": hosts_read(parsed),
        "hosts_seen": hosts_seen(parsed), "permission_denials": permission_denials(parsed),
        "stderr_tail": (stderr or "")[-300:],
    }
    (d / "run.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


# ── scoring and comparison ─────────────────────────────────────────────────

def _rec_ungated(r: dict) -> float | None:
    dims = [r.get("nr"), (r.get("rq_meta") or {}).get("node_pct")]
    if r.get("er") is not None:
        dims.append(r["er"])
    if r.get("mk") is not None:
        dims.append(r["mk"])
    dims = [x for x in dims if x is not None]
    return round(sum(dims) / len(dims), 1) if dims else None


def score_dir(label: str, d: Path, arm: str | None = None) -> dict | None:
    case, negative, _ = case_for(label)
    if not (d / "graph.json").exists():
        return None
    if negative:
        r = scorer.score_negative(dict(case), str(d))
    else:
        r = scorer.score_case(dict(case), str(d))
        r["rec_ungated"] = _rec_ungated(r)
        r["actor_hit"] = (r.get("rq_meta") or {}).get("actor_hit")
        r["n_attribution"] = sum(1 for n in json.loads((d / "graph.json").read_text())["nodes"]
                                 if n["type"] in ("actor", "malware", "ransomware", "framework",
                                                  "phishing_kit", "kit", "tool", "campaign"))
    run = d / "run.json"
    r["has_run_json"] = run.exists()
    if run.exists():
        r["run"] = json.loads(run.read_text())
    stream = d / "stream.jsonl"
    if stream.exists():
        # The stream is the record; run.json may come from an older version of
        # this script. Re-derive what was read from it.
        parsed = parse_stream(stream.read_text(encoding="utf-8").splitlines())
        r.setdefault("run", {}).update({"hosts_read": hosts_read(parsed),
                                         "hosts_seen": hosts_seen(parsed),
                                         "permission_denials": permission_denials(parsed)})
    run = r.get("run") or {}
    if arm in ARMS:
        # A run without a fingerprint predates it: its brief is unknown, so stale.
        r.setdefault("run", {})["stale_brief"] = run.get("prompt_sha") != prompt_sha(build_prompt(case, arm))
    if not negative and ("hosts_read" in run or "hosts_seen" in run):
        r["run"]["answer_key"] = answer_key(case["case_id"], run.get("hosts_read") or [],
                                            run.get("hosts_seen") or [])
    return r


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 1) if xs else None


def _fmt(x) -> str:
    if x is None:
        return "–"
    if isinstance(x, bool):
        return "yes" if x else "no"
    return f"{x:.1f}" if isinstance(x, float) else str(x)


def compare(out: Path, bounce: Path | None, labels: list[str]) -> dict:
    sides: dict[str, dict[str, dict]] = {}
    for arm in ARMS:
        if (out / arm).is_dir():
            sides[arm] = {}
            for label in labels:
                _, _, dname = case_for(label)
                r = score_dir(label, out / arm / dname, arm)
                if r is not None:
                    sides[arm][label] = r
    if bounce is not None:
        sides["bounce"] = {}
        for label in labels:
            _, _, dname = case_for(label)
            r = score_dir(label, bounce / dname)
            if r is not None:
                sides["bounce"][label] = r
    return sides


def render_md(sides: dict, labels: list[str], title: str, notes: list[str]) -> str:
    order = [s for s in ("bounce", "web", "memory") if s in sides]
    name = {"bounce": "Bounce-CTI", "web": "bare model + web", "memory": "bare model, memory only"}
    pos = [l for l in labels if not l.upper().startswith("N")]
    neg = [l for l in labels if l.upper().startswith("N")]
    out = [f"# {title}", ""]
    out += notes + [""]
    out += ["## Recall on the fresh subset (same scorer, same ground truth)", "",
            "REC here is ungated: mean of NR, COV, ER and MK whether or not the live data has "
            "decayed, so the three sides are averaged over the same dimensions.", "",
            "| Case | Side | NR | ER | MK | COV | REC | Actor named | Attributions | "
            "Untraceable | Tool calls |",
            "|---|---|---:|---:|---:|---:|---:|:---:|---:|---:|---:|"]
    for l in pos:
        for s in order:
            r = sides[s].get(l)
            if not r or "error" in r:
                out.append(f"| {l} | {name[s]} | – | – | – | – | – | – | – | – | – |")
                continue
            calls = r["cti_calls"] if s == "bounce" else len((r.get("run") or {}).get("tool_calls") or [])
            n_att = r.get("n_attribution")
            flag = " ⚠️ other brief" if (r.get("run") or {}).get("stale_brief") else ""
            out.append(
                f"| {l} | {name[s]}{flag} | {_fmt(r['nr'])} | {_fmt(r['er'])} | {_fmt(r['mk'])} | "
                f"{_fmt((r.get('rq_meta') or {}).get('node_pct'))} | {_fmt(r['rec_ungated'])} | "
                f"{_fmt(r['actor_hit'])} | {_fmt(n_att)} | {len(r['hallucinations'])} | {calls} |")
    out += ["", "| Side | NR mean | REC mean | Cases with the actor named | Untraceable attributions |",
            "|---|---:|---:|---:|---:|"]
    for s in order:
        rs = [sides[s][l] for l in pos if l in sides[s] and "error" not in sides[s][l]]
        out.append(f"| {name[s]} | {_fmt(_mean(r['nr'] for r in rs))} | "
                   f"{_fmt(_mean(r['rec_ungated'] for r in rs))} | "
                   f"{sum(1 for r in rs if r['actor_hit'])}/{len(rs)} | "
                   f"{sum(len(r['hallucinations']) for r in rs)} |")
    if neg:
        out += ["", "## Restraint on benign seeds (RST: 100 = no cluster, no attribution)", "",
                "| Case | " + " | ".join(name[s] for s in order) + " |",
                "|---|" + "---:|" * len(order)]
        for l in neg:
            out.append(f"| {l} | " + " | ".join(_fmt((sides[s].get(l) or {}).get("rst"))
                                                 for s in order) + " |")
    web = sides.get("web") or {}
    if web:
        out += ["", "## What the web arm read", "",
                "The ground truth comes from public write-ups (`cases.GT_SOURCE_HOSTS`). "
                "\"Answer key\" says whether the web arm fetched that write-up, met it in a search "
                "result's snippet, or did not reach it.", ""]
        for l in pos + neg:
            run = (web.get(l) or {}).get("run") or {}
            hosts = run.get("hosts_read") or []
            seen = [h for h in run.get("hosts_seen") or [] if h not in hosts]
            more = f" (+{len(seen) - 12} more in results.json)" if len(seen) > 12 else ""
            denied = run.get("permission_denials") or 0
            key = run.get("answer_key")
            out.append(f"- **{l}**" + (f" (answer key: **{key}**)" if key else "")
                       + f": fetched {', '.join(hosts) if hosts else '(nothing)'}"
                       + (f"; in search results also {', '.join(seen[:12])}{more}" if seen else "")
                       + (f" ⚠️ {denied} tool call(s) refused by the CLI" if denied else ""))
    out.append("")
    return "\n".join(out)


def _slim(sides: dict) -> dict:
    keep = ("case_id", "name", "nr", "nr_hits", "nr_total", "nr_missing", "er", "mk", "rq_meta",
            "rec_ungated", "actor_hit", "n_attribution", "hallucinations", "cti_calls", "cap",
            "data_decayed", "rst", "attribution", "promoted", "nodes")
    slim = {}
    for s, rows in sides.items():
        slim[s] = {}
        for l, r in rows.items():
            row = {k: r[k] for k in keep if k in r}
            run = r.get("run") or {}
            row["run"] = {k: run.get(k) for k in ("model", "cli", "wall_s", "num_turns", "timed_out",
                                                  "answer_parsed", "tool_calls", "hosts_read",
                                                  "hosts_seen", "permission_denials", "answer_key",
                                                  "prompt_sha", "stale_brief")
                          if k in run}
            slim[s][l] = row
    return slim


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--arm", choices=sorted(ARMS), required=True)
    r.add_argument("--model", required=True, help="pin the exact model id (e.g. claude-opus-5)")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--claude", default=os.environ.get("CLAUDE_BIN") or "claude")
    r.add_argument("--seeds", type=Path, help="a prospective batch's seeds.json (EVAL_PROTOCOL "
                   "§4.E): its labels are run instead of cases.py's")
    r.add_argument("cases", nargs="+")
    c = sub.add_parser("compare")
    c.add_argument("--out", type=Path, required=True)
    c.add_argument("--bounce", type=Path)
    c.add_argument("--title", default="Bounce-CTI against the same model without it")
    c.add_argument("--note", action="append", default=[])
    c.add_argument("--bounce-model", default="", help="model the Bounce-CTI run used, as its "
                   "init event logged it (graph data does not carry it)")
    c.add_argument("--date", default="", help="run date for the published digest (YYYY-MM-DD)")
    c.add_argument("--write", action="store_true", help="write results.json and results.md in --out")
    c.add_argument("cases", nargs="*", default=[str(x) for x in FRESH_SUBSET] + ["N1", "N2", "N3"])
    args = ap.parse_args(argv)
    if args.cmd == "run":
        seeds = load_seeds(args.seeds) if args.seeds else None
        unknown = [l for l in args.cases if seeds is not None and l not in seeds]
        if unknown:
            print(f"not in {args.seeds}: {', '.join(unknown)}", file=sys.stderr)
            return 2
        for label in args.cases:
            meta = run_case(label, args.arm, args.model, args.out, args.claude, seeds)
            print(json.dumps({k: meta[k] for k in ("case", "arm", "model", "wall_s", "num_turns",
                                                    "answer_parsed", "timed_out",
                                                    "permission_denials")}), flush=True)
        return 0
    sides = compare(args.out, args.bounce, args.cases)
    md = render_md(sides, args.cases, args.title, args.note)
    stale = sorted(f"{s}/{l}" for s, rows in sides.items() for l, r in rows.items()
                   if (r.get("run") or {}).get("stale_brief"))
    if args.write and stale:
        print(md)
        no_meta = [k for k in stale if not sides[k.split("/")[0]][k.split("/", 1)[1]].get("has_run_json")]
        other = [k for k in stale if k not in no_meta]
        if no_meta:
            print(f"refusing to write results: {', '.join(no_meta)} have no run.json, so the brief "
                  "they ran on is unknown (re-run them)", file=sys.stderr)
        if other:
            print(f"refusing to write results: {', '.join(other)} ran on another brief than this "
                  "checkout's (re-run them)", file=sys.stderr)
        return 1
    if args.write:
        models = {s: sorted({(r.get("run") or {}).get("model") for r in rows.values()} - {None})
                  for s, rows in sides.items() if s != "bounce"}
        if "bounce" in sides:
            models["bounce"] = [args.bounce_model] if args.bounce_model else []
        doc = {"meta": {"date": args.date, "models": models, "cases": args.cases},
               "sides": _slim(sides)}
        (args.out / "results.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        (args.out / "results.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
