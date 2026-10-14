#!/usr/bin/env python3
"""Manage the source-response fixture sets under eval/fixtures/ (EVAL_PROTOCOL §4.C).

    python eval/fixture_tool.py promote <inv_id> <case>   # capture → eval/fixtures/<case>/
    python eval/fixture_tool.py verify [<case> ...]       # integrity + no secret (exit 1 if not)
    python eval/fixture_tool.py stats <case>              # responses and bytes per source

Capture itself happens in the backend (``BOUNCE_FIXTURE_CAPTURE=1``, see
backend/fixtures.py): each investigation records into
``data/fixtures/capture/<inv_id>/``. ``promote`` turns one of those into the
committed fixture set of an eval case, replacing the previous set entirely (a
case's responses come from ONE capture, or replay would mix two worlds), writes
its MANIFEST.md and runs ``verify`` on the result.

``verify`` is the gate before a commit: every file must parse, sit under the name
its key hashes to, and carry no secret. "No secret" is checked two ways: the
values of the secret-looking vars of this checkout's ``.env`` must not appear
anywhere, and nothing may look like a credential (``key=…``, ``token=…``,
``Bearer …``) unless it is a ``<secret:…>`` placeholder.

Stdlib only; run from anywhere.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import fixtures  # noqa: E402  (stdlib-only module)

FIXTURES_DIR = ROOT / "eval" / "fixtures"
CAPTURE_DIR = ROOT / "data" / "fixtures" / "capture"
MANIFEST = "MANIFEST.md"

_CREDENTIAL_SHAPES = [
    re.compile(r"(?i)\b(?:api_?key|apikey|key|token|access_token|auth|secret)"
               r"=(?!<secret:)[^&\s\"'<>]{12,}"),
    re.compile(r"(?i)\bbearer\s+(?!<secret:)[A-Za-z0-9._~+/-]{20,}"),
    re.compile(r"\bflgrn_octi_tkn_[A-Za-z0-9]+"),
]


def _fixture_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.glob("*.json") if p.name != fixtures.ENV_FILE)


def _dotenv_secrets(path: Path) -> list[tuple[str, str]]:
    """(name, value) for the secret-looking entries of a .env file."""
    out = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, raw = line.partition("=")
        name = name.strip()
        if not fixtures.is_secret_name(name):
            continue
        for value in raw.strip().strip("\"'").split(","):
            value = value.strip()
            if len(value) >= 8:
                out.append((name, value))
    return out


def verify(directory: Path, dotenv: Path | None = None,
           warnings: list[str] | None = None) -> list[str]:
    """Problems found in one fixture set (empty list = clean). Doubtful but
    non-fatal findings are appended to ``warnings`` when given."""
    problems = []
    warnings = warnings if warnings is not None else []
    if not directory.is_dir():
        return [f"{directory}: not a directory"]
    known = _dotenv_secrets(dotenv if dotenv is not None else ROOT / ".env")
    env_file = directory / fixtures.ENV_FILE
    if env_file.exists():
        try:
            doc = json.loads(env_file.read_text(encoding="utf-8"))
            names = doc.get("secret_env_names")
            if set(doc) != {"secret_env_names"} or not isinstance(names, list) \
                    or not all(isinstance(n, str) and fixtures.is_secret_name(n)
                               for n in names):
                problems.append(f"{env_file.name}: must hold secret env var NAMES only")
        except ValueError as e:
            problems.append(f"{env_file.name}: invalid JSON ({e})")
    for path in [*_fixture_files(directory), *([env_file] if env_file.exists() else [])]:
        text = path.read_text(encoding="utf-8")
        for name, value in known:
            if value in text:
                problems.append(f"{path.name}: contains the value of {name} from .env")
        if path == env_file:
            continue
        try:
            doc = json.loads(text)
        except ValueError as e:
            problems.append(f"{path.name}: invalid JSON ({e})")
            continue
        if not isinstance(doc, dict) or not {"key", "source", "value"} <= set(doc):
            problems.append(f"{path.name}: missing key/source/value")
            continue
        if fixtures.fixture_name(doc["key"]) != path.name:
            problems.append(f"{path.name}: name does not match its key {doc['key']!r}")
        if text != fixtures.serialise(doc["key"], doc["value"]):
            problems.append(f"{path.name}: not in canonical form (hand-edited?)")
        # A cache key is built by OUR code from the request: a credential shape
        # there is our own key leaking. In a value it is usually threat data (a
        # phishing URL with a token in it), so it is reported, not fatal.
        for shape in _CREDENTIAL_SHAPES:
            m = shape.search(doc["key"])
            if m:
                problems.append(f"{path.name}: credential-shaped key {m.group(0)[:24]!r}…")
            m = shape.search(json.dumps(doc["value"], ensure_ascii=False))
            if m:
                warnings.append(f"{path.name}: credential-shaped text in the response "
                                f"{m.group(0)[:24]!r}… (threat data, or a leak? look)")
    return problems


def stats(directory: Path) -> dict[str, dict[str, int]]:
    per = defaultdict(lambda: {"responses": 0, "bytes": 0})
    for path in _fixture_files(directory):
        doc = json.loads(path.read_text(encoding="utf-8"))
        per[doc.get("source", "?")]["responses"] += 1
        per[doc.get("source", "?")]["bytes"] += path.stat().st_size
    return dict(sorted(per.items()))


def _manifest(case: str, inv_id: str, directory: Path) -> str:
    per = stats(directory)
    total = sum(v["responses"] for v in per.values())
    size = sum(v["bytes"] for v in per.values())
    lines = [
        f"# Fixture set `{case}`",
        "",
        f"Captured from investigation `{inv_id}`, promoted "
        f"{time.strftime('%Y-%m-%d', time.gmtime())}. "
        f"{total} source responses, {size:,} bytes.",
        "",
        "Replay it with `BOUNCE_FIXTURE_DIR=eval/fixtures/" + case + "` "
        "(EVAL_PROTOCOL §4.C). Generated by `eval/fixture_tool.py promote`; do not edit.",
        "",
        "| source | responses | bytes |",
        "|---|---:|---:|",
    ]
    lines += [f"| {s} | {v['responses']} | {v['bytes']:,} |" for s, v in per.items()]
    lines += ["", "## Keys", ""]
    keys = sorted(json.loads(p.read_text(encoding="utf-8"))["key"]
                  for p in _fixture_files(directory))
    lines += [f"- `{k}`" for k in keys]
    return "\n".join(lines) + "\n"


def promote(inv_id: str, case: str, capture_root: Path = CAPTURE_DIR,
            fixtures_root: Path = FIXTURES_DIR, dotenv: Path | None = None,
            warnings: list[str] | None = None) -> list[str]:
    src = capture_root / inv_id
    if not src.is_dir() or not _fixture_files(src):
        return [f"{src}: no captured responses (was BOUNCE_FIXTURE_CAPTURE=1 on "
                f"when that investigation ran?)"]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", case):
        return [f"{case!r}: a case name is letters, digits, '-' and '_' only"]
    dst = fixtures_root / case
    if dst.exists():
        for p in [*dst.glob("*.json"), dst / MANIFEST]:
            if p.exists():
                p.unlink()
    dst.mkdir(parents=True, exist_ok=True)
    for p in [*_fixture_files(src), src / fixtures.ENV_FILE]:
        if p.exists():
            shutil.copy2(p, dst / p.name)
    (dst / MANIFEST).write_text(_manifest(case, inv_id, dst), encoding="utf-8")
    return verify(dst, dotenv, warnings)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    dotenv_help = ("the .env whose secrets must not appear (default: this checkout's; "
                   "pass the capturing instance's, e.g. /opt/bounce-cti/.env)")
    p = sub.add_parser("promote", help="capture of an investigation → eval/fixtures/<case>/")
    p.add_argument("inv_id")
    p.add_argument("case")
    p.add_argument("--capture-root", type=Path, default=CAPTURE_DIR,
                   help="where the captures live (default: this checkout's data/fixtures/"
                        "capture; point it at the deployed instance's, and run promote "
                        "from a working checkout: files left untracked in a deployed "
                        "checkout block its next git pull)")
    p.add_argument("--dotenv", type=Path, help=dotenv_help)
    p = sub.add_parser("verify", help="integrity and secret check (exit 1 on a problem)")
    p.add_argument("cases", nargs="*")
    p.add_argument("--dotenv", type=Path, help=dotenv_help)
    p = sub.add_parser("stats", help="responses and bytes per source")
    p.add_argument("case")
    args = ap.parse_args(argv)

    warnings: list[str] = []
    if args.cmd == "promote":
        problems = promote(args.inv_id, args.case, args.capture_root,
                           dotenv=args.dotenv, warnings=warnings)
        target = FIXTURES_DIR / args.case
    elif args.cmd == "verify":
        cases = args.cases
        if not cases and FIXTURES_DIR.is_dir():
            cases = sorted(p.name for p in FIXTURES_DIR.iterdir() if p.is_dir())
        problems = []
        for case in cases:
            found: list[str] = []
            problems += [f"{case}/{p}" for p in verify(FIXTURES_DIR / case, args.dotenv,
                                                       warnings=found)]
            warnings += [f"{case}/{w}" for w in found]
        print(f"{len(cases)} fixture set(s) checked")
        target = None
    else:
        for source, v in stats(FIXTURES_DIR / args.case).items():
            print(f"{source:24} {v['responses']:5} responses {v['bytes']:>10,} bytes")
        return 0

    for w in warnings:
        print(f"⚠ {w}")
    for p in problems:
        print(f"✗ {p}")
    if problems:
        return 1
    if target is not None:
        print(f"✓ {target.relative_to(ROOT)}: {sum(v['responses'] for v in stats(target).values())} "
              f"responses, verified")
    else:
        print("✓ clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
