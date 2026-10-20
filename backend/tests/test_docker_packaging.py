"""The Docker packaging keeps three promises that nothing else checks.

* No secret and no database inside an image: ``.env`` (API keys, ADMIN_PIN, Claude
  auth) and ``data/`` stay out of the build context, and the Dockerfile takes no
  secret as a build argument or baked environment variable (both end up in the
  image history). ``.env`` reaches the container as a read-only bind mount.
* The app is published on the host's loopback only. It speaks plain HTTP and its
  session cookie is ``Secure``: fine on http://localhost, wrong anywhere else.
* The process does not run as root: ``claude -p --permission-mode
  bypassPermissions`` refuses to start as root, so every phase would die.

Plain text parsing, no Docker and no YAML library needed.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Continuation lines joined, so `ENV A=1 \` + `    B=2` reads as one instruction.
DOCKERFILE = re.sub(r"\\\n", " ", (ROOT / "Dockerfile").read_text(encoding="utf-8"))
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
SECRET_NAMES = ("API_KEY", "TOKEN", "PIN", "SECRET", "PASSWORD")


def _dockerignore_rules() -> list[tuple[bool, re.Pattern]]:
    """(excludes, regex) per line, in order. Docker anchors patterns at the context
    root, `*` stays inside one path segment, `**` spans segments, `!` re-includes."""
    rules = []
    for raw in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        pat = line[1:] if neg else line
        pat = pat.strip("/")
        rx = ""
        i = 0
        while i < len(pat):
            if pat.startswith("**/", i):
                rx += "(?:.*/)?"
                i += 3
            elif pat.startswith("**", i):
                rx += ".*"
                i += 2
            elif pat[i] == "*":
                rx += "[^/]*"
                i += 1
            elif pat[i] == "?":
                rx += "[^/]"
                i += 1
            else:
                rx += re.escape(pat[i])
                i += 1
        rules.append((not neg, re.compile(rx + r"\Z")))
    return rules


def _excluded(path: str) -> bool:
    """Is `path` (relative, with /) left out of the build context? A rule matching the
    path or one of its parent directories applies; the last matching rule wins."""
    parts = path.split("/")
    prefixes = ["/".join(parts[: n + 1]) for n in range(len(parts))]
    verdict = False
    for excludes, rx in _dockerignore_rules():
        if any(rx.match(p) for p in prefixes):
            verdict = excludes
    return verdict


def _final_stage(dockerfile: str) -> str:
    return re.split(r"(?mi)^FROM\s", dockerfile)[-1]


def test_secrets_and_state_stay_out_of_the_build_context():
    for path in (".env", ".env.local", ".env.production", "data/bounce.db",
                 "data/fixtures/capture/abc/x.json", "bounce.db", ".git/config"):
        assert _excluded(path), f"{path} would be copied into the image"


def test_what_the_image_needs_is_in_the_build_context():
    for path in ("backend/main.py", "backend/mcp_servers/cti_mcp.py", "run_mcp.py",
                 "mcp.json", "requirements.txt", ".env.example",
                 "frontend/package.json", "frontend/package-lock.json",
                 "frontend/index.html", "frontend/src/App.jsx", "eval/demo/README.md"):
        assert not _excluded(path), f"{path} is missing from the build context"
        assert (ROOT / path).exists(), f"{path} named here no longer exists"


def test_dockerignore_matcher_follows_docker_semantics():
    # The matcher above is what the two tests rely on: pin its behaviour.
    assert _excluded("frontend/node_modules/vite/package.json")   # **/node_modules/
    assert _excluded("backend/__pycache__/main.cpython-312.pyc")  # **/__pycache__/
    assert not _excluded("backend/data_helpers.py")               # `data/` is anchored
    assert not _excluded(".env.example")                          # re-included by `!`


def test_no_secret_is_baked_into_the_image():
    assert not re.search(r"(?mi)^\s*(COPY|ADD)\s+[^\n]*\.env(\s|$)", DOCKERFILE)
    for m in re.finditer(r"(?mi)^\s*(ARG|ENV)\s+([^\n]+)", DOCKERFILE):
        names = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", m.group(2)) or [m.group(2).split()[0]]
        for name in names:
            assert not any(s in name.upper() for s in SECRET_NAMES), (
                f"{m.group(1)} {name}: a secret here is readable in the image history")


def test_runtime_runs_the_app_as_a_non_root_user():
    final = _final_stage(DOCKERFILE)
    users = re.findall(r"(?mi)^\s*USER\s+(\S+)", final)
    assert users, "the runtime stage never leaves root"
    assert users[-1].split(":")[0] not in ("root", "0")
    assert re.search(r'(?m)^CMD\s+\[\s*"uvicorn",\s*"backend\.main:app"', final)
    # The built frontend comes from the build stage, where StaticFiles expects it.
    assert re.search(r"(?m)^COPY\s+[^\n]*--from=frontend\s+/build/frontend/dist\s+\./frontend/dist", final)


def test_compose_publishes_on_loopback_only():
    ports = re.findall(r'(?m)^\s*-\s*"?([0-9.:]+)"?\s*(?:#.*)?$', COMPOSE.split("ports:", 1)[1].split("volumes:", 1)[0])
    assert ports, "no published port found"
    for p in ports:
        assert p.count(":") == 2 and p.startswith("127.0.0.1:"), f"{p} is reachable beyond localhost"


def test_compose_mounts_env_read_only_and_never_creates_it():
    block = COMPOSE.split("source: ./.env", 1)
    assert len(block) == 2, ".env is not bind-mounted"
    mount = block[1].split("- ", 1)[0]
    assert "target: /app/.env" in mount
    assert re.search(r"read_only:\s*true", mount)
    assert re.search(r"create_host_path:\s*false", mount)
