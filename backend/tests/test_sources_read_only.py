"""Bounce-CTI only reads from the feeds it queries (EVAL_PROTOCOL §4.E, "the gesture
that makes its own confirmation"). A public submission (an urlscan scan, a URL
sent to VirusTotal, an IOC submitted to ThreatFox) can put a claim into a feed
before a prospective batch is judged, and the judge would then count it as found
"ahead". It is also a disclosure: a submitted victim URL is published.

Checked on the code, not by eye: every request in ``backend/sources/`` and in
the prospective judge (``backend/eval_judge.py``) that is not a GET must go to an
endpoint listed below, each one a lookup that only reads; an abuse.ch ``query``
must be a read verb; no upload (``files=``); no known submission path; no
GraphQL mutation. A new POST fails this test until its endpoint is added here
with the reason it reads."""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# http_client.py is the transport: post_json / post_form are checked at every call site.
SCANNED = sorted(p for p in (ROOT / "backend" / "sources").glob("*.py") if p.name != "http_client.py") \
    + [ROOT / "backend" / "eval_judge.py"]

# Non-GET endpoints that only read, and why.
READ_ONLY_POSTS = {
    "https://urlhaus-api.abuse.ch/v1/host/": "URLhaus host lookup",
    "https://urlhaus-api.abuse.ch/v1/url/": "URLhaus URL lookup",
    "https://mb-api.abuse.ch/api/v1/": "MalwareBazaar query API (verbs checked below; uploads need files=)",
    "https://threatfox-api.abuse.ch/api/v1/": "ThreatFox query API (verbs checked below)",
    "https://hashlookup.circl.lu/bulk/": "CIRCL hashlookup bulk lookup",
    "http://ip-api.com/batch": "ip-api batch geolocation",
    "{OPENCTI_URL}/graphql": "OpenCTI GraphQL (no mutation, checked below)",
    "https://checkurl.phishtank.com/checkurl/": "PhishTank URL check",
    "https://google.serper.dev/search": "Serper web search",
}
# abuse.ch read verbs. Submissions share the same endpoints: ThreatFox
# "submit_ioc", MalwareBazaar "upload" (with a file). ThreatFox "ioc" reads one
# entry by its id (the judge's positive control, backend/eval_judge.py).
READ_VERB = re.compile(r"^(get_[a-z_]+|search_[a-z_]+|taginfo|malwareinfo|ioc)$")
# Paths that submit, whatever the method that reaches them.
SUBMISSION_MARKERS = (
    "urlscan.io/api/v1/scan",        # urlscan: a public scan by default
    "submit_ioc",                    # ThreatFox submission
    "upload_url", "/analyse",        # VirusTotal upload, re-analysis
    "/api/v2/report",                # AbuseIPDB: reporting an IP
    "/submit",                       # Hybrid Analysis, PhishTank add, generic
    "json_data",                     # MalwareBazaar upload form
)
WRITE_METHODS = {"post", "put", "patch", "delete"}
WRITE_HELPERS = {"post_json", "post_form"}


def _consts(tree: ast.AST) -> dict[str, str]:
    """Module-level ``NAME = "string"`` constants."""
    out = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = node.value.value
    return out


def _template(node, consts: dict, local: dict) -> str | None:
    """A URL argument as a string; an unknown name inside an f-string stays
    ``{NAME}``, a call or an unknown variable is None (unresolvable)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in local:
            return _template(local[node.id], consts, {})
        return consts.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name):
                parts.append(consts.get(v.value.id, "{" + v.value.id + "}"))
            else:
                parts.append("{?}")
        return "".join(parts)
    return None


def _write_calls(tree: ast.AST):
    """(call, url node or None, local assignments of its function) for every
    request that is not a GET. Each call is read with the assignments of its
    innermost function (``url = f"{BASE}/x"`` then ``post(url)``)."""
    owner: dict[int, ast.AST] = {}
    for fn in ast.walk(tree):  # outer before inner: the innermost function wins
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                owner[id(n)] = fn
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        fn = owner.get(id(call))
        local = {t.id: n.value for n in ast.walk(fn) if isinstance(n, ast.Assign)
                 for t in n.targets if isinstance(t, ast.Name)} if fn is not None else {}
        method = _write_method(call)
        if not method:
            continue
        if _name(call) == "request":
            url = call.args[1] if len(call.args) > 1 else None
        else:
            url = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "url"), None)
        yield call, url, local


def _name(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _write_method(call: ast.Call) -> str | None:
    """The write method of a call, or None (a GET, or not a request)."""
    name = _name(call)
    if name in WRITE_HELPERS or name in WRITE_METHODS:
        return name
    if name == "request" and call.args and isinstance(call.args[0], ast.Constant) \
            and str(call.args[0].value).lower() in WRITE_METHODS:
        return str(call.args[0].value).lower()
    if name == "Request":   # urllib.request.Request(url, data=..., method="POST")
        m = next((k.value for k in call.keywords if k.arg == "method"), None)
        if isinstance(m, ast.Constant) and str(m.value).lower() in WRITE_METHODS:
            return str(m.value).lower()
    return None


def findings(path: Path, text: str | None = None) -> list[str]:
    text = text if text is not None else path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    consts = _consts(tree)
    out = []
    for call, url, local in _write_calls(tree):
        where = f"{path.name}:{call.lineno}"
        if any(k.arg == "files" for k in call.keywords):
            out.append(f"{where}: an upload (files=)")
        if path.name == "eval_judge.py" and isinstance(url, ast.Name) and url.id == "url":
            continue  # the judge's own helpers: their callers' constants are checked below
        tpl = _template(url, consts, local) if url is not None else None
        if tpl is None:
            out.append(f"{where}: a non-GET request to an endpoint this test cannot read")
        elif not any(tpl.startswith(p) for p in READ_ONLY_POSTS):
            out.append(f"{where}: a non-GET request to {tpl}, not a known read-only endpoint")
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "query" and isinstance(v, ast.Constant) \
                        and isinstance(v.value, str) and not READ_VERB.match(v.value) \
                        and "abuse.ch" in text:
                    out.append(f"{path.name}:{node.lineno}: abuse.ch query {v.value!r} is not a read verb")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            for marker in SUBMISSION_MARKERS:
                if marker in low:
                    out.append(f"{path.name}:{node.lineno}: a submission endpoint ({marker})")
            if re.search(r"\bmutation\s*[{(a-z]", low) and "graphql" in text.lower():
                out.append(f"{path.name}:{node.lineno}: a GraphQL mutation")
    if path.name == "eval_judge.py":
        for name, value in consts.items():
            if value.startswith("http") and "otx.alienvault.com" not in value \
                    and not any(value.startswith(p) for p in READ_ONLY_POSTS):
                out.append(f"eval_judge.py: {name} = {value}, not a known read-only endpoint")
    return out


def test_sources_and_the_judge_only_read():
    problems = [f for p in SCANNED for f in findings(p)]
    assert problems == []


def test_the_check_catches_each_kind_of_submission():
    # Each snippet is what a well-meant change could add; each must be caught.
    snippets = {
        "urlscan scan": 'async def f(u):\n    return await post_json("https://urlscan.io/api/v1/scan/", json_body={"url": u})\n',
        "threatfox submit": 'async def f(i):\n    return await post_json("https://threatfox-api.abuse.ch/api/v1/", json_body={"query": "submit_ioc", "iocs": [i]})\n',
        "mb update (a write on the read endpoint)": 'async def f(h):\n    return await post_form("https://mb-api.abuse.ch/api/v1/", form_data={"query": "update", "sha256_hash": h, "key": "tags", "value": "x"})\n',
        "mb upload": 'async def f(b):\n    return await c.post("https://mb-api.abuse.ch/api/v1/", files={"file": b})\n',
        "vt url submit": 'B = "https://www.virustotal.com/api/v3"\nasync def f(u):\n    return await c.post(f"{B}/urls", data={"url": u})\n',
        "unreadable": 'async def f(u):\n    return await c.post(make_url(u))\n',
        "put": 'async def f(u):\n    return await c.put("https://example.org/x")\n',
        "request POST": 'async def f(u):\n    return await c.request("POST", "https://urlscan.io/api/v1/scan/")\n',
        "urllib POST": 'import urllib.request\ndef f(u):\n    return urllib.request.Request("https://example.org/add", data=b"x", method="POST")\n',
        "mutation": 'Q = "mutation { indicatorAdd(input: {}) { id } }"\nasync def f():\n    return await c.post(f"{OPENCTI_URL}/graphql", json={"query": Q})  # graphql\n',
        "criminalip scan by POST": '_BASE = "https://api.criminalip.io/v1"\nasync def f(d):\n    return await post_json(f"{_BASE}/domain/scan", json_body={"query": d})\n',
    }
    for label, code in snippets.items():
        assert findings(Path("snippet.py"), code), f"not caught: {label}"


def test_the_reads_in_use_today_pass():
    ok = 'async def f(h):\n    return await post_form("https://mb-api.abuse.ch/api/v1/", form_data={"query": "get_info", "hash": h})\n'
    assert findings(Path("snippet.py"), ok + "# abuse.ch\n") == []
    get = '_BASE = "https://api.criminalip.io/v1"\nasync def f(d):\n    return await get_json(f"{_BASE}/domain/scan")\n'
    assert findings(Path("snippet.py"), get) == []  # a GET is not a submission (it answers 405, see the note)
