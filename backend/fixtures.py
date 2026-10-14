"""Fixture capture and offline replay of source responses (EVAL_PROTOCOL §4.C).

A live eval run is non-deterministic twice over: the data decays (domains get
parked, feeds roll over, a source is down that hour) and the agent samples. This
module removes the first variable. It records the response of every source call
an investigation makes, and can later serve those exact responses with the
network switched off, so two runs on the same code see the same data.

What it does NOT pin: the agent's own choices. A replayed agent that asks a
question the captured run never asked gets a *miss*, which is served as a
network failure that names itself (``fixture replay: …``). The miss count, read
from the run's event log, is the measure of how far a replay drifted from its
capture.

Where it hooks — one layer, so a new source is covered without touching it:

* ``graph_store.cache_get`` / ``cache_set``. Every source already memoises its
  responses in the ``cache`` table under a source-specific key; capture
  records those keys (on a write AND on a hit, since a warm cache still
  answered the agent), replay answers them from the fixture set and never
  writes replay traffic into a database.
* ``dns_tools`` is the one source with no cache entry; it goes through
  :func:`through`.
* :func:`install_offline_guard` refuses DNS lookups and socket connects in the
  MCP server process during replay, so a miss can never fall back to the live
  internet (and a placeholder API key can never leave the box).

Env vars (read on every call, so a test can flip them):

``BOUNCE_FIXTURE_DIR``          replay from this fixture set (e.g.
                                ``eval/fixtures/case02``; relative paths are
                                resolved against the project root).
``BOUNCE_FIXTURE_CAPTURE_DIR``  record into this directory. Set per
                                investigation by ``agent_runner`` when
                                ``BOUNCE_FIXTURE_CAPTURE=1``; not meant to be
                                set by hand.
``BOUNCE_FIXTURE_MISSES``       replay only: append each miss to this JSONL
                                file (``agent_runner`` sets one per
                                investigation, so the drift of a replay is a
                                line count).

Replay wins when both are set. Neither set (the default, and production) =
no file I/O and no behaviour change.

Secrets: a fixture set is meant to be committed to a public repo. The value of
every env var whose NAME contains KEY, TOKEN, SECRET, PASSWORD, PASSWD, AUTH or
CREDENTIAL (so ``NETLAS_APIKEY`` too, not only ``*_API_KEY``), plus
``OPENCTI_URL``, is replaced by a placeholder (``<secret:SHODAN>``) in both the
key and the value before anything is written, and a write that still contains
one is refused. Values shorter than 8 characters are left alone (they would
redact ordinary text); ``eval/fixture_tool.py verify`` checks the capturing
``.env`` again before a commit. Lookups apply the same
redaction, which is what lets a replay with no real key find a capture made
with one.

Stdlib only, no backend imports: ``graph_store`` imports this module, and
``run_mcp.py`` calls :func:`activate_for_process` before ``backend.config``
reads the environment.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPLAY_ENV = "BOUNCE_FIXTURE_DIR"
CAPTURE_ENV = "BOUNCE_FIXTURE_CAPTURE_DIR"
MISSES_ENV = "BOUNCE_FIXTURE_MISSES"

# Cache keys that hold the platform's own bookkeeping, not a source's answer.
# They are per-run state (budgets, dead-source marks, uploaded context) and must
# be recomputed by the replayed run, never served from a fixture.
# backend/tests/test_fixtures.py fails when a module outside backend/sources/
# starts using the cache, so a new kind of key gets classified here on purpose.
BOOKKEEPING_PREFIXES = (
    "counter|",        # graph_store per-investigation counters (budgets)
    "source_health|",  # source_health dead-source marks
    "pdf_source:",     # main.py: IOC context from an uploaded PDF
    "sample_source:",  # main.py: context from an uploaded sample
)

ENV_FILE = "_env.json"   # names (never values) of the secrets present at capture
REPLAY_MISS = "fixture replay"

# Broad on purpose: a false positive only redacts a harmless value, a miss
# publishes a key.
_SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|AUTH|CREDENTIAL")
# Narrower: the credential variables a replay stands in with a placeholder.
# Redaction must be broad; standing in must not touch SSH_AUTH_SOCK and kin.
_CREDENTIAL_NAME = re.compile(r"(API_?KEYS?|_KEYS?|_TOKEN|_SECRET|_PASSWORD|_PASSWD)$")
_SECRET_EXTRA = ("OPENCTI_URL",)  # may point at a private instance
_MIN_SECRET_LEN = 8               # shorter values would redact ordinary text


# ── Mode ──────────────────────────────────────────────────────────────────

def _path_from_env(name: str) -> Optional[Path]:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return None
    p = Path(raw)
    return p if p.is_absolute() else PROJECT_ROOT / p


def replay_dir() -> Optional[Path]:
    return _path_from_env(REPLAY_ENV)


def capture_dir() -> Optional[Path]:
    if replay_dir() is not None:
        return None
    return _path_from_env(CAPTURE_ENV)


def replaying() -> bool:
    return replay_dir() is not None


def capturing() -> bool:
    return capture_dir() is not None


def is_source_key(key: str) -> bool:
    return isinstance(key, str) and not key.startswith(BOOKKEEPING_PREFIXES)


_GENERIC_VERBS = ("GET", "POST", "TXT", "FORM")  # http_client's default keys


def source_of(key: str) -> str:
    """The source a key belongs to, for the manifest: ``shodan|/dns/…`` →
    shodan; http_client's default ``GET|https://rdap.org/…|None`` → rdap.org."""
    head, sep, rest = key.partition("|")
    if sep and head in _GENERIC_VERBS:
        url = rest.split("|", 1)[0]
        host = url.split("://", 1)[-1].split("/", 1)[0]
        return host or head
    for sep in ("|", ":"):
        if sep in key:
            return key.split(sep, 1)[0]
    return key


# ── Secrets ───────────────────────────────────────────────────────────────

def secret_placeholder(name: str) -> str:
    """One placeholder per source, whatever the spelling of its env var:
    SHODAN_API_KEY, SHODAN_API_KEYS and SHODAN_KEY all become <secret:SHODAN>."""
    base = re.sub(r"_(API_)?KEYS?$", "", name)
    return f"<secret:{base}>"


def is_secret_name(name: str) -> bool:
    return bool(_SECRET_NAME.search(name.upper())) or name in _SECRET_EXTRA


def is_credential_name(name: str) -> bool:
    """A variable that holds a source credential (SHODAN_API_KEY, NETLAS_APIKEY,
    OPENCTI_API_KEYS, ABUSECH_AUTH_KEY, OPENCTI_URL), as opposed to anything
    else that only needs redacting."""
    return bool(_CREDENTIAL_NAME.search(name.upper())) or name in _SECRET_EXTRA


def _secrets() -> list[tuple[str, str]]:
    """(value, placeholder) for every secret in the environment, longest first."""
    out: dict[str, str] = {}
    for name, raw in os.environ.items():
        if not raw or not is_secret_name(name):
            continue
        for value in raw.split(","):
            value = value.strip()
            if len(value) >= _MIN_SECRET_LEN:
                out.setdefault(value, secret_placeholder(name))
    return sorted(out.items(), key=lambda kv: len(kv[0]), reverse=True)


def redact(text: str) -> str:
    for value, placeholder in _secrets():
        text = text.replace(value, placeholder)
    return text


def leaked_secret(text: str) -> Optional[str]:
    """The placeholder of a secret still present in ``text``, if any."""
    for value, placeholder in _secrets():
        if value in text:
            return placeholder
    return None


# ── Files ─────────────────────────────────────────────────────────────────

def fixture_name(redacted_key: str) -> str:
    return hashlib.sha256(redacted_key.encode("utf-8")).hexdigest()[:24] + ".json"


def serialise(redacted_key: str, value: Any) -> str:
    """Canonical text of one fixture: stable bytes for the same response, so a
    re-capture of unchanged data is an empty git diff. The response keeps its
    own key order, which is the order the agent read it in."""
    doc = {"key": redacted_key, "source": source_of(redacted_key), "value": value}
    return json.dumps(doc, ensure_ascii=False, indent=1) + "\n"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _warn(msg: str) -> None:
    print(f"[fixtures] {msg}", file=sys.stderr)


_env_written: set[str] = set()


def _write_env_names(directory: Path) -> None:
    """Record which secret env vars existed at capture (names only), so a
    replay can stand in placeholders for exactly those and no others: a source
    that had no key at capture must still answer "no key" in replay."""
    if str(directory) in _env_written:
        return
    names = sorted({n for n, v in os.environ.items() if v and is_credential_name(n)})
    _atomic_write(directory / ENV_FILE,
                  json.dumps({"secret_env_names": names}, indent=1) + "\n")
    _env_written.add(str(directory))


def record(key: str, value: Any) -> None:
    """Capture one source response. Never raises: a capture problem must not
    break the live investigation it is observing."""
    directory = capture_dir()
    if directory is None or not is_source_key(key):
        return
    try:
        rk = redact(key)
        text = redact(serialise(rk, value))
        leak = leaked_secret(text)
        if leak:  # defence in depth; redact() should have made this impossible
            _warn(f"refused to record {source_of(rk)}: {leak} still present")
            return
        _write_env_names(directory)
        _atomic_write(directory / fixture_name(rk), text)
    except Exception as e:
        _warn(f"capture failed for {source_of(key)}: {type(e).__name__}: {e}")


def load(directory: Path, key: str) -> tuple[bool, Any]:
    """(found, value) for ``key`` in the fixture set at ``directory``."""
    rk = redact(key)
    path = directory / fixture_name(rk)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False, None
    if doc.get("key") != rk:  # a hash collision, or a hand-edited file
        _warn(f"{path.name} holds {doc.get('key')!r}, not {rk!r}: ignored")
        return False, None
    return True, doc.get("value")


_misses: list[str] = []


def _note_miss(key: str) -> None:
    rk = redact(key)
    _misses.append(rk)
    _warn(f"{REPLAY_MISS}: no recorded response for {rk!r}")
    log = _path_from_env(MISSES_ENV)
    if log is None:
        return
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"key": rk, "source": source_of(rk)},
                               ensure_ascii=False) + "\n")
    except OSError as e:
        _warn(f"could not log the miss to {log}: {e}")


def replay_get(key: str) -> Any:
    """The recorded value for ``key``, or None: a miss. The caller then fails
    the way a dead network fails (http_client says so by name; anything else
    runs into the offline guard)."""
    found, value = load(replay_dir(), key)
    if not found:
        _note_miss(key)
    return value


def misses() -> list[str]:
    """Keys this process asked for and the fixture set did not have."""
    return list(_misses)


async def through(key: str, fetch: Callable[[], Awaitable[Any]]) -> Any:
    """Fixture layer for a source that keeps no cache entry (DNS). Live: just
    ``fetch()``. Capture: ``fetch()`` and record. Replay: the recorded value;
    on a miss, ``fetch()`` runs into the offline guard and degrades the way the
    source already degrades on a network failure."""
    if replaying():
        found, value = load(replay_dir(), key)
        if found:
            return value
        _note_miss(key)
        return await fetch()
    value = await fetch()
    if capturing():
        record(key, value)
    return value


# ── Replay process setup ──────────────────────────────────────────────────

def stand_in_secrets(directory: Path) -> list[str]:
    """Give every secret that existed at capture a placeholder value, unless the
    environment already has one. Sources check for a key BEFORE they look in the
    cache, so without this a keyless replay would answer "no key configured"
    where the capture got data. The placeholder redacts to the same
    ``<secret:…>`` as the real key did, so the lookup finds the capture."""
    try:
        names = json.loads((directory / ENV_FILE).read_text(encoding="utf-8")).get(
            "secret_env_names", [])
    except (FileNotFoundError, ValueError):
        return []
    set_now = []
    for name in names:
        if is_credential_name(name) and not os.environ.get(name):
            os.environ[name] = f"fixture-replay-{name}"
            set_now.append(name)
    return set_now


class _NetworkDisabled(OSError):
    pass


def _is_local(address: Any) -> bool:
    """A Unix socket path or a literal loopback IP: this machine, not the
    internet. asyncio needs it (on Windows its self-pipe is a loopback
    socketpair). A host NAME is never local here: resolving it goes through the
    refused getaddrinfo, so ``localhost`` stays blocked."""
    if isinstance(address, (str, bytes)):
        return True
    if isinstance(address, tuple) and address and isinstance(address[0], str):
        try:
            return ipaddress.ip_address(address[0].split("%", 1)[0]).is_loopback
        except ValueError:
            return False
    return False


def install_offline_guard() -> Callable[[], None]:
    """Refuse name resolution and every socket that would leave this machine,
    in this process. Returns the function that puts everything back (tests use
    it; the MCP server never does). The MCP stdio transport and SQLite use no
    sockets, and loopback stays open for the event loop's own plumbing."""
    def _refused(what: str, target: Any) -> _NetworkDisabled:
        return _NetworkDisabled(
            f"{REPLAY_MISS}: network disabled, no recorded response "
            f"({what} {redact(str(target))})")

    # sendmsg does not exist on Windows: guard what the platform has.
    methods = [m for m in ("connect", "connect_ex", "sendto", "sendmsg")
               if hasattr(socket.socket, m)]
    saved = {"getaddrinfo": socket.getaddrinfo,
             **{m: getattr(socket.socket, m) for m in methods}}

    def getaddrinfo(host, *args, **kwargs):
        raise _refused("resolve", host)

    def guarded_connect(name):
        real = saved[name]

        def connect(self, address):
            if not _is_local(address):
                raise _refused("connect", address)
            return real(self, address)
        return connect

    def sendto(self, data, *args):
        address = args[-1] if args else None
        if not _is_local(address):
            raise _refused("sendto", address)
        return saved["sendto"](self, data, *args)

    def sendmsg(self, buffers, *args):
        # The address is the 4th parameter; without it the socket is already
        # connected, and its connect went through the guard.
        if len(args) >= 3 and args[2] is not None and not _is_local(args[2]):
            raise _refused("sendmsg", args[2])
        return saved["sendmsg"](self, buffers, *args)

    guards = {"connect": guarded_connect("connect"),
              "connect_ex": guarded_connect("connect_ex"),
              "sendto": sendto, "sendmsg": sendmsg}
    socket.getaddrinfo = getaddrinfo
    for m in methods:
        setattr(socket.socket, m, guards[m])

    def restore() -> None:
        socket.getaddrinfo = saved["getaddrinfo"]
        for m in methods:
            setattr(socket.socket, m, saved[m])
    return restore


def activate_for_process() -> str:
    """Called by run_mcp.py before any backend import. Returns a one-line mode
    description for the launcher log."""
    directory = replay_dir()
    if directory is not None:
        if not directory.is_dir():
            # Fail loud: a typo here would otherwise replay an empty set, i.e.
            # a run where every source "failed", scored as if it were real.
            raise SystemExit(f"{REPLAY_ENV}={directory} is not a directory")
        stood_in = stand_in_secrets(directory)
        install_offline_guard()
        return (f"fixtures: REPLAY from {directory} (offline; "
                f"{len(stood_in)} placeholder key(s))")
    directory = capture_dir()
    if directory is not None:
        return f"fixtures: CAPTURE into {directory}"
    return "fixtures: off"
