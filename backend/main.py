"""FastAPI entry point: REST + WebSocket for live graph updates.

Auth: session cookie. All /api/* and /ws/* require it except /api/auth/login
and /api/auth/logout. Investigations are scoped to the authenticated user.

Admin (`is_admin=1`) can manage users via /api/admin/users and is not
restricted to any subset of models.
"""
import asyncio
import os
import time
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, Response, Cookie, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

from . import graph_store as gs
from . import auth
from . import seeds
from . import verticals
from .agent_runner import (
    run_investigation, run_pivot, run_add_seed, run_custom_prompt,
    stop_investigation, resume_investigation, quota_block_active,
)
from .refang import refang

app = FastAPI(title="Bounce-CTI")
# Tight CORS: the frontend is served from the same origin as the API.
app.add_middleware(CORSMiddleware, allow_origins=[], allow_methods=["*"], allow_headers=["*"])


ALLOWED_MODELS = ["sonnet", "opus", "opus-4.7", "opus-4.8", "haiku"]
DEFAULT_MODEL = "opus"

# Extended-thinking effort levels accepted by the Claude CLI (`--effort` /
# CLAUDE_CODE_EFFORT_LEVEL). None / "" means "use the CLI default". Stored per
# investigation and applied to every phase spawn by agent_runner._build_env.
ALLOWED_EFFORTS = ["low", "medium", "high", "xhigh", "max"]

SESSION_COOKIE = "session"


def _check_effort(effort: Optional[str]) -> Optional[str]:
    """Sanitize a requested thinking-effort level. Returns the level if valid,
    else None (CLI default). Never raises — an unknown value silently degrades
    to the default rather than failing the spawn."""
    if not effort:
        return None
    effort = str(effort).strip().lower()
    return effort if effort in ALLOWED_EFFORTS else None


# ── Startup: ensure admin PIN exists ───────────────────────────────────────
@app.on_event("startup")
def _bootstrap():
    auth.bootstrap_admin(os.getenv("ADMIN_PIN"))


# ── Live WebSocket registry (for shutdown broadcast) ───────────────────────
# Every connected /ws/{inv_id} adds itself here and removes on disconnect. On
# uvicorn shutdown (e.g. `systemctl restart bounce-cti`) we send a one-off
# `server_shutdown` frame to each client so the UI can show a banner and
# reconnect when the service comes back, instead of silently going dead.
_active_ws: set[WebSocket] = set()


@app.on_event("shutdown")
async def _notify_ws_shutdown():
    """Tell every connected client the service is about to restart."""
    for ws in list(_active_ws):
        try:
            await ws.send_json({
                "kind": "server_shutdown",
                "message": "Service is restarting, reconnecting soon…",
            })
        except Exception:
            pass
        try:
            await ws.close(code=1012)  # RFC 6455: service restart
        except Exception:
            pass
        _active_ws.discard(ws)


# ── Auth dependencies ──────────────────────────────────────────────────────
def current_user(session: Optional[str] = Cookie(default=None)) -> int:
    uid = auth.resolve_session(session)
    if uid is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return uid


def current_admin(user_id: int = Depends(current_user)) -> int:
    u = auth.get_user(user_id)
    if not u or not u["is_admin"]:
        raise HTTPException(status_code=403, detail="admin required")
    return user_id


def _resolve_allowed_models(user_id: int) -> Optional[list[str]]:
    """Return the user's allowed-models whitelist, or None for no restriction."""
    u = auth.get_user(user_id)
    if not u:
        return []
    if u["is_admin"]:
        return None  # admin: unrestricted
    return u["allowed_models"]  # None (unrestricted) or list


def _check_model(user_id: int, model: str) -> str:
    """Validate `model` against ALLOWED_MODELS *and* the user's whitelist.
    Returns the sanitized model string, or raises 403."""
    if model not in ALLOWED_MODELS:
        model = DEFAULT_MODEL
    allowed = _resolve_allowed_models(user_id)
    if allowed is not None and model not in allowed:
        raise HTTPException(status_code=403, detail=f"model '{model}' not allowed for this user")
    return model


def _client_ip(request: Request) -> str:
    # Caddy sets X-Forwarded-For; fall back to direct peer.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _require_quota_available():
    """Refuse to spawn a new Claude agent if the subscription is in a known
    cooldown window. Returns 429 with the reset epoch so the frontend can show
    a countdown + Resume affordance instead of silently failing."""
    blocked, reset_at, msg = quota_block_active()
    if blocked:
        retry_after = max(1, int((reset_at or 0) - time.time())) if reset_at else 60
        raise HTTPException(
            status_code=429,
            detail={
                "error": "claude_quota_exhausted",
                "message": msg or "Claude subscription quota reached",
                "reset_at": reset_at,
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )


def _set_session_cookie(response: Response, token: str):
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=auth.SESSION_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


# ── Auth routes ────────────────────────────────────────────────────────────
class LoginReq(BaseModel):
    pin: str


@app.post("/api/auth/login")
def auth_login(req: LoginReq, request: Request, response: Response):
    ip = _client_ip(request)
    if auth.is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="too many attempts, try again later")
    user_id = auth.verify_pin(req.pin, ip)
    if user_id is None:
        raise HTTPException(status_code=401, detail="invalid PIN")
    token = auth.issue_session(user_id)
    _set_session_cookie(response, token)
    return {"ok": True}


@app.post("/api/auth/logout")
def auth_logout(response: Response, session: Optional[str] = Cookie(default=None)):
    auth.destroy_session(session)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def auth_me(user_id: int = Depends(current_user)):
    u = auth.get_user(user_id)
    if not u:
        raise HTTPException(status_code=401, detail="not authenticated")
    return {
        "user_id": u["id"],
        "is_admin": u["is_admin"],
        "allowed_models": u["allowed_models"],  # None → unrestricted
    }


# ── Admin routes ───────────────────────────────────────────────────────────
class CreateUserReq(BaseModel):
    allowed_models: Optional[list[str]] = None  # None/[] → unrestricted
    label: Optional[str] = None                 # short human-readable name


@app.get("/api/admin/users")
def admin_list_users(_: int = Depends(current_admin)):
    return {"users": gs.get_users_with_stats(), "all_models": ALLOWED_MODELS}


@app.post("/api/admin/users")
def admin_create_user(req: CreateUserReq, _: int = Depends(current_admin)):
    allowed = req.allowed_models or None
    if allowed:
        bad = [m for m in allowed if m not in ALLOWED_MODELS]
        if bad:
            raise HTTPException(status_code=400, detail=f"unknown models: {bad}")
    uid, pin = auth.create_user(allowed_models=allowed, label=req.label)
    return {"id": uid, "pin": pin}


class UpdateUserReq(BaseModel):
    allowed_models: Optional[list[str]] = None  # None/[] → unrestricted
    label: Optional[str] = None                 # None means "leave unchanged"


@app.patch("/api/admin/users/{target_id}")
def admin_update_user(target_id: int, req: UpdateUserReq, _: int = Depends(current_admin)):
    # allowed_models: treat None as "leave unchanged" only when the key is absent
    # from the JSON payload. Pydantic gives us None for missing keys too, so we
    # use .model_fields_set (or __fields_set__) to distinguish.
    fields = getattr(req, "model_fields_set", None) or getattr(req, "__fields_set__", set())
    if "allowed_models" in fields:
        allowed = req.allowed_models or None
        if allowed:
            bad = [m for m in allowed if m not in ALLOWED_MODELS]
            if bad:
                raise HTTPException(status_code=400, detail=f"unknown models: {bad}")
        gs.update_user_allowed_models(target_id, allowed)
    if "label" in fields:
        gs.update_user_label(target_id, req.label)
    return {"ok": True}


@app.delete("/api/admin/users/{target_id}")
def admin_delete_user(target_id: int, admin_id: int = Depends(current_admin)):
    if target_id == admin_id:
        raise HTTPException(status_code=400, detail="cannot delete yourself")
    target = auth.get_user(target_id)
    if target and target["is_admin"]:
        raise HTTPException(status_code=400, detail="cannot delete another admin")
    gs.delete_user(target_id)
    return {"ok": True}


@app.post("/api/admin/impersonate/{target_id}")
def admin_impersonate(target_id: int, response: Response, admin_id: int = Depends(current_admin)):
    target = auth.get_user(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="user not found")
    token = auth.issue_session(target_id)
    _set_session_cookie(response, token)
    return {"ok": True, "user_id": target_id}


@app.get("/api/admin/lessons_learned")
def admin_lessons_learned(limit: int = 200, _: int = Depends(current_admin)):
    """Return the most recent lessons-learned entries emitted by the agent at
    the end of investigations. Backed by `data/lessons_learned.jsonl`.

    ``limit`` caps the response size (default 200, max 1000)."""
    import json as _json
    from .agent_runner import LESSONS_LEDGER_PATH
    limit = max(1, min(int(limit or 200), 1000))
    if not LESSONS_LEDGER_PATH.exists():
        return {"entries": [], "total": 0}
    # Read the last `limit` lines without slurping the whole file. The ledger
    # is JSONL so we can scan line-by-line; even at 10k entries it stays small.
    lines: list[str] = []
    try:
        with LESSONS_LEDGER_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"could not read ledger: {e}")
    tail = lines[-limit:]
    entries: list[dict] = []
    for ln in tail:
        try:
            entries.append(_json.loads(ln))
        except Exception:
            continue
    entries.reverse()  # newest first
    return {"entries": entries, "total": len(lines)}


# ── Core routes (all scoped to user_id) ────────────────────────────────────
def _require_owner(inv_id: str, user_id: int):
    owner = gs.get_investigation_owner(inv_id)
    # owner may be None for legacy investigations; only the user's own ones are accessible
    if owner != user_id:
        raise HTTPException(status_code=404, detail="not found")


@app.get("/api/models")
def list_models(user_id: int = Depends(current_user)):
    allowed = _resolve_allowed_models(user_id)
    models = ALLOWED_MODELS if allowed is None else [m for m in ALLOWED_MODELS if m in allowed]
    default = DEFAULT_MODEL if (allowed is None or DEFAULT_MODEL in allowed) else (models[0] if models else DEFAULT_MODEL)
    return {"models": models, "default": default, "efforts": ALLOWED_EFFORTS}


# Single source of truth: the seed registry. (Was a hand-maintained literal —
# identical set, now derived so adding a seed type in backend/seeds.py is enough.)
ALLOWED_SEED_TYPES = set(seeds.KNOWN_SEED_TYPES)

import re

# Unambiguous executable / script extensions — chosen to avoid TLD collisions
# (no .com, .app, .bin, .so, .sh, .jar, .pkg, .deb, .rpm, .swf, .reg, etc.).
# When auto-detect is on, a value like "malware.exe" or "C:\\Users\\foo\\dropper.dll"
# is classified as `executable_name` instead of falling through to `domain`.
_EXEC_EXTENSIONS = (
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "hta",
    "pif", "wsh", "wsf", "jse", "msi", "ocx", "drv", "lnk", "dylib", "elf",
)

_RE_URL = re.compile(r"^(https?|ftp)://", re.I)
_RE_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_RE_IPV6 = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_RE_ASN = re.compile(r"^(asn?)\s*\d{1,10}$", re.I)
_RE_JARM = re.compile(r"^[0-9a-fA-F]{62}$")
_RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_RE_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_RE_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")
_RE_DOMAIN = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_RE_EXECUTABLE_NAME = re.compile(
    r"^[^\s<>|?*\"]+\.(" + "|".join(_EXEC_EXTENSIONS) + r")$",
    re.I,
)
# RFC 5322-ish email — pragmatic, not exhaustive.
_RE_EMAIL = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
# Cryptocurrency wallet detection. We only auto-classify when the format is
# unambiguous (ETH 0x prefix, BTC bech32 bc1 / tb1 prefix). The legacy BTC
# Base58 forms (P2PKH/P2SH) collide with arbitrary strings, so we require
# a leading 1 or 3 plus the canonical length window and Base58 alphabet.
_RE_WALLET_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
_RE_WALLET_BTC_BECH32 = re.compile(r"^(bc1|tb1)[a-z0-9]{6,87}$")
_RE_WALLET_BTC_BASE58 = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_RE_WALLET_XMR = re.compile(r"^[48][1-9A-HJ-NP-Za-km-z]{94}$")
# Usernames are intentionally not auto-detected — too generic. The frontend
# (and API) pass seed_type=username explicitly when the analyst means it.


def detect_seed_type(value: str) -> str:
    """Auto-detect the IOC type from a refanged value."""
    v = refang(value).strip()
    if not v:
        return "domain"
    if _RE_URL.match(v):
        return "url"
    if _RE_ASN.match(v):
        return "asn"
    if _RE_IPV4.match(v):
        return "ip"
    if _RE_IPV6.match(v):
        return "ip"
    if _RE_EMAIL.match(v):
        return "email"
    if _RE_WALLET_ETH.match(v):
        return "wallet_address"
    if _RE_WALLET_BTC_BECH32.match(v):
        return "wallet_address"
    if _RE_WALLET_XMR.match(v):
        return "wallet_address"
    # Legacy BTC Base58 — checked AFTER hash/exec/domain because the
    # 1.../3... pattern collides with arbitrary IOC strings.
    if _RE_JARM.match(v):
        return "jarm"
    if _RE_SHA256.match(v):
        return "hash"
    if _RE_SHA1.match(v):
        return "hash"
    if _RE_MD5.match(v):
        return "hash"
    if _RE_WALLET_BTC_BASE58.match(v):
        return "wallet_address"
    # Executable filename before domain: "malware.exe" matches both _RE_DOMAIN
    # and _RE_EXECUTABLE_NAME, and the filename interpretation is what the
    # analyst pasting a binary's basename actually wants.
    if _RE_EXECUTABLE_NAME.match(v):
        return "executable_name"
    if _RE_DOMAIN.match(v):
        return "domain"
    return "domain"


def _clean_seed(seed_type: str, seed_value: str) -> str:
    """Refang + strip a seed_value. For ASN, also normalize to bare digits
    with an optional AS prefix so `AS13335`, `as13335`, `13335` all hash to
    the same node id."""
    sv = refang((seed_value or "")).strip()
    if seed_type == "asn":
        m = sv.upper().lstrip().removeprefix("ASN").removeprefix("AS").strip()
        # keep only digits — drop stray punctuation
        digits = "".join(ch for ch in m if ch.isdigit())
        sv = f"AS{digits}" if digits else sv
    elif seed_type == "jarm":
        # JARM fingerprints are 62-char lowercase hex-ish; normalize case + trim.
        sv = sv.lower()
    elif seed_type == "executable_name":
        # Strip surrounding quotes, drop any path component (Windows or POSIX),
        # lowercase so "Malware.EXE" and "malware.exe" hash to the same node.
        sv = sv.strip("\"'")
        for sep in ("\\", "/"):
            if sep in sv:
                sv = sv.rsplit(sep, 1)[-1]
        sv = sv.lower()
    elif seed_type == "email":
        # Email addresses are case-insensitive on the domain part and
        # almost-always-treated-case-insensitive on the local part. We
        # lower-case the whole thing so "Foo@Bar.com" and "foo@bar.com"
        # hash to the same node.
        sv = sv.lower()
    elif seed_type == "wallet_address":
        # ETH addresses use EIP-55 mixed case for checksum. Keep case for
        # ETH; lower-case Bech32 (BTC bc1/tb1) for canonical form.
        if _RE_WALLET_BTC_BECH32.match(sv) or sv.lower().startswith(("bc1", "tb1")):
            sv = sv.lower()
        # Base58 (BTC legacy, XMR) and ETH 0x stay as provided.
    elif seed_type == "username":
        # Strip a leading @ if the analyst pasted "@handle". Keep case —
        # some identifiers are case-sensitive (e.g. GitHub).
        sv = sv.lstrip("@")
    return sv


class StartReq(BaseModel):
    seed_type: str = "auto"
    seed_value: str
    model: str = "opus"
    effort: Optional[str] = None
    vertical: str = "cti"


@app.post("/api/investigations")
async def start(req: StartReq, user_id: int = Depends(current_user)):
    _require_quota_available()
    model = _check_model(user_id, req.model)
    effort = _check_effort(req.effort)
    vertical = verticals.normalise(req.vertical)
    seed_type = req.seed_type
    if seed_type == "auto":
        seed_type = detect_seed_type(req.seed_value)
    if seed_type not in ALLOWED_SEED_TYPES:
        raise HTTPException(status_code=400, detail=f"unknown seed_type: {seed_type}")
    sv = _clean_seed(seed_type, req.seed_value)
    if not sv:
        raise HTTPException(status_code=400, detail="seed_value required")
    inv_id = gs.create_investigation(seed_type, sv, user_id=user_id, model=model,
                                     effort=effort, vertical=vertical)
    asyncio.create_task(run_investigation(inv_id, seed_type, sv, model=model))
    return {"id": inv_id, "seed_type": seed_type, "vertical": vertical}


class BatchItem(BaseModel):
    seed_type: str = "auto"
    seed_value: str


class BatchStartReq(BaseModel):
    items: list[BatchItem]
    model: str = "opus"
    effort: Optional[str] = None
    combined: bool = False  # True → all IOCs on a single investigation graph


@app.post("/api/investigations/batch")
async def start_batch(req: BatchStartReq, user_id: int = Depends(current_user)):
    """Kick off many investigations at once.

    When `combined=false` (default): one investigation per IOC (parallel).
    When `combined=true`: one investigation seeded from the first IOC,
    then each additional IOC is launched as a pivot on that same graph
    so the agent can find cross-IOC links.
    """
    _require_quota_available()
    model = _check_model(user_id, req.model)
    effort = _check_effort(req.effort)
    items = req.items[:50]
    valid = []
    for it in items:
        st = it.seed_type if it.seed_type != "auto" else detect_seed_type(it.seed_value)
        if st not in ALLOWED_SEED_TYPES:
            continue
        sv = _clean_seed(st, it.seed_value)
        if not sv:
            continue
        valid.append((st, sv))
    if not valid:
        return {"started": [], "skipped": len(req.items)}

    if req.combined and len(valid) >= 1:
        # Combined batch: single investigation, extra IOCs added as PEER seeds
        # sequentially after the main investigation finishes. This avoids the
        # race where a second agent runs concurrently on a half-built graph,
        # and ensures each new seed sees prior infrastructure for cross-seed
        # detection. Peer-seed semantics live in run_add_seed's prompt —
        # the agent won't invent edges between seeds.
        st0, sv0 = valid[0]
        inv_id = gs.create_investigation(st0, sv0, user_id=user_id, model=model, effort=effort)
        extra_seeds = valid[1:]
        # Pre-register the extra seeds as orphan seed-tagged nodes so the
        # listing panel shows the full multi-seed count immediately, instead
        # of only revealing them after each run_add_seed cycle finishes.
        # We use gs.add_node directly (not the MCP wrapper) so no pivots are
        # auto-enqueued — that work happens later in run_add_seed. The
        # `pending_seed` tag marks them as not-yet-investigated; run_add_seed
        # upserts and the agent's normal "seed" workflow takes over.
        for _st, _sv in extra_seeds:
            gs.add_node(inv_id, _st, _sv, metadata={}, source="batch",
                        tags=["seed", "pending_seed"])

        async def _combined_chain(_iid=inv_id, _primary=(st0, sv0), _extras=extra_seeds):
            import json as _json, time as _time
            await run_investigation(_iid, _primary[0], _primary[1], model=model)
            for _st, _sv in _extras:
                gs.set_status(_iid, "running")
                # Clear the pending_seed marker now that this seed is being
                # actively investigated. The node was pre-registered above so
                # the listing panel could show the full seed count from t=0.
                from .graph_store import _node_id as _nid
                gs.set_node_tag(_iid, _nid(_iid, _st, _sv), "pending_seed", on=False)
                with gs.conn() as c:
                    payload = {"kind": "status_change", "status": "running",
                               "add_seed_type": _st, "add_seed_value": _sv}
                    c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                              (_iid, "status_change", _json.dumps(payload), _time.time()))
                await run_add_seed(_iid, _st, _sv, model=model)

        asyncio.create_task(_combined_chain())
        return {"started": [{"id": inv_id, "seed_type": st0, "seed_value": sv0,
                             "combined": True, "total_seeds": len(valid)}],
                "skipped": len(req.items) - len(valid)}
    else:
        # Separate batch: one investigation per IOC
        ids = []
        for st, sv in valid:
            inv_id = gs.create_investigation(st, sv, user_id=user_id, model=model, effort=effort)
            asyncio.create_task(run_investigation(inv_id, st, sv, model=model))
            ids.append({"id": inv_id, "seed_type": st, "seed_value": sv})
        return {"started": ids, "skipped": len(req.items) - len(ids)}


@app.get("/api/investigations")
def list_inv(user_id: int = Depends(current_user)):
    return gs.list_investigations(user_id=user_id)


@app.get("/api/investigations/{inv_id}/graph")
def graph(inv_id: str, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    return gs.get_graph(inv_id)


@app.get("/api/investigations/{inv_id}/nodes/{node_id}/cross_investigations")
def node_cross_investigations(inv_id: str, node_id: str,
                               limit: int = 25,
                               user_id: int = Depends(current_user)):
    """Return prior investigations (owned by the caller) where a node with
    the same (type, value) tuple already appeared. Surfaces cross-campaign
    infrastructure reuse — when a registrant email / JARM / C2 IP shows up
    in multiple investigations, that's a high-signal pivot the analyst
    should not miss.

    The node is resolved by ``node_id`` in the current investigation; the
    lookup itself is by (type, value) across the user's full history,
    excluding the current investigation. Up to ``limit`` rows, most recent
    first.
    """
    _require_owner(inv_id, user_id)
    with gs.conn() as c:
        row = c.execute(
            "SELECT type, value FROM nodes WHERE investigation_id=? AND id=?",
            (inv_id, node_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="node not found")
    hits = gs.find_node_across_investigations(
        row["type"], row["value"], user_id=user_id,
        exclude_inv=inv_id, limit=min(max(1, int(limit)), 100),
    )
    return {"type": row["type"], "value": row["value"], "hits": hits, "count": len(hits)}


@app.get("/api/investigations/{inv_id}/transcript")
def transcript(inv_id: str, user_id: int = Depends(current_user)):
    """Return the agent's reasoning + tool-call transcript, ordered.

    Used by the UI to rebuild the timeline after page reload (live WS events
    only cover the current session — historical reasoning lives in the
    events table). Each entry is one of:
      {"kind": "reasoning", "ts": <epoch>, "text": "...", "phase": "..."}
      {"kind": "tool",      "ts": <epoch>, "name": "...", "input": {...}}
      {"kind": "tool_result","ts":<epoch>, "name": "...", "result_preview": "..."}
      {"kind": "phase",     "ts": <epoch>, "phase": "main|followup|...", "stage": "starting|exit"}
    Tool inputs are kept as-is; tool results are truncated to 800 chars for
    rendering compactness — the full JSON is still in the events table for
    deep audit if ever needed.
    """
    _require_owner(inv_id, user_id)
    out: list[dict] = []
    events = gs.get_events_since(inv_id, 0)
    tool_use_id_to_name: dict[str, str] = {}
    for e in events:
        ts = e.get("_ts") or 0
        kind = e.get("kind") or ""
        msg = e.get("msg") or e.get("data") or {}
        if kind == "agent_assistant":
            content = (msg.get("message") or {}).get("content") or []
            for block in content:
                btype = block.get("type")
                if btype == "text":
                    txt = (block.get("text") or "").strip()
                    if txt:
                        out.append({"kind": "reasoning", "ts": ts, "text": txt})
                elif btype == "tool_use":
                    name = block.get("name") or "?"
                    inp = block.get("input") or {}
                    tool_use_id = block.get("id")
                    if tool_use_id:
                        tool_use_id_to_name[tool_use_id] = name
                    out.append({"kind": "tool", "ts": ts, "name": name, "input": inp})
        elif kind == "agent_user":
            # Synthetic "user" events from the SDK carry tool results back.
            content = (msg.get("message") or {}).get("content") or []
            for block in content:
                if block.get("type") == "tool_result":
                    tool_use_id = block.get("tool_use_id") or ""
                    name = tool_use_id_to_name.get(tool_use_id, "?")
                    raw = block.get("content")
                    if isinstance(raw, list):
                        preview = " ".join(
                            (b.get("text") or "")[:800] for b in raw
                            if isinstance(b, dict) and b.get("type") == "text"
                        )[:800]
                    elif isinstance(raw, str):
                        preview = raw[:800]
                    else:
                        preview = ""
                    is_error = bool(block.get("is_error"))
                    out.append({"kind": "tool_result", "ts": ts, "name": name,
                                "result_preview": preview, "is_error": is_error})
        elif kind.startswith("phase_") and kind.endswith(("_starting", "_exit")):
            stage = "starting" if kind.endswith("_starting") else "exit"
            phase = kind[len("phase_"):-len(f"_{stage}")]
            out.append({"kind": "phase", "ts": ts, "phase": phase, "stage": stage})
    return {"investigation_id": inv_id, "entries": out}


@app.get("/api/quota")
def get_quota(user_id: int = Depends(current_user)):
    """Report the Claude-subscription quota state for the host account.

    The frontend polls this to show a global banner + countdown when bounce
    is in a cooldown window after a `claude -p` invocation returned a usage
    limit error. `exhausted_until` is a unix epoch (seconds).
    """
    return gs.get_quota_state()


@app.post("/api/investigations/{inv_id}/resume")
async def resume_inv(inv_id: str, user_id: int = Depends(current_user)):
    """Resume a `quota_exceeded` investigation once the cooldown is over.

    The graph is preserved (phases self-skip when their work is already done),
    and the pivot-drain loop picks up where it stopped. Returns 425 if the
    reset epoch hasn't passed yet so the user has to wait."""
    _require_owner(inv_id, user_id)
    blocked, reset_at, msg = quota_block_active()
    if blocked:
        retry_after = max(1, int((reset_at or 0) - time.time())) if reset_at else 60
        raise HTTPException(
            status_code=425,
            detail={"error": "still_in_cooldown", "reset_at": reset_at,
                    "retry_after_seconds": retry_after, "message": msg},
            headers={"Retry-After": str(retry_after)},
        )
    with gs.conn() as c:
        row = c.execute(
            "SELECT seed_type, seed_value, model FROM investigations WHERE id=?",
            (inv_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    model = _check_model(user_id, row["model"] or DEFAULT_MODEL)
    asyncio.create_task(resume_investigation(inv_id, model=model))
    return {"ok": True}


@app.post("/api/investigations/{inv_id}/stop")
def stop_inv(inv_id: str, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    killed = stop_investigation(inv_id)
    if killed:
        gs.set_status(inv_id, "done")
        import json as _json, time as _time
        with gs.conn() as c:
            payload = {"kind": "status_change", "status": "done", "stopped_by_user": True}
            c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                      (inv_id, "status_change", _json.dumps(payload), _time.time()))
    return {"ok": True, "killed": killed}


@app.delete("/api/investigations/{inv_id}")
def delete_inv(inv_id: str, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    stop_investigation(inv_id)  # kill agent if running before deleting
    gs.delete_investigation(inv_id)
    return {"ok": True}


class RenameReq(BaseModel):
    title: Optional[str] = None


@app.patch("/api/investigations/{inv_id}")
def rename_inv(inv_id: str, req: RenameReq, user_id: int = Depends(current_user)):
    """Rename an investigation. Empty title clears it (UI falls back to seed)."""
    _require_owner(inv_id, user_id)
    ok = gs.rename_investigation(inv_id, req.title)
    if not ok:
        raise HTTPException(status_code=404, detail="not found")
    return {"ok": True, "title": (req.title or "").strip()[:120] or None}


class MergeReq(BaseModel):
    delete_source: bool = False


@app.post("/api/investigations/{src_id}/merge_into/{dst_id}")
def merge_investigations(src_id: str, dst_id: str,
                         req: Optional[MergeReq] = None,
                         user_id: int = Depends(current_user)):
    """Merge `src_id` into `dst_id`, both owned by the caller.

    Same dedup semantics as the share-link import path: nodes are upserted
    on `(inv, type, value)`, edges on `(inv, src, dst, relation)`. Metadata,
    tags, and `sources_seen` are unioned. The destination's existing report
    node is preserved (the source report is dropped to avoid clobbering the
    caller's analysis).

    Default behaviour leaves `src_id` intact so the analyst can audit the
    merge and undo by deleting the destination if needed. Pass
    `delete_source=true` to remove the source after a successful merge.
    """
    if src_id == dst_id:
        raise HTTPException(status_code=400, detail="source and destination must differ")
    _require_owner(src_id, user_id)
    _require_owner(dst_id, user_id)
    # Refuse to merge a still-running source — its graph is half-built and
    # the agent might keep adding nodes after the merge, leaving them
    # orphaned in the source. Stop it first if you really want to merge.
    src_status = None
    with gs.conn() as c:
        row = c.execute("SELECT status FROM investigations WHERE id=?", (src_id,)).fetchone()
        if row:
            src_status = row["status"]
    if src_status == "running":
        raise HTTPException(status_code=409,
                            detail="source investigation is still running — stop it before merging")
    result = gs.merge_into_investigation(src_id, dst_id)
    if (req and req.delete_source):
        stop_investigation(src_id)
        gs.delete_investigation(src_id)
        result["source_deleted"] = True
    else:
        result["source_deleted"] = False
    return {"id": dst_id, "mode": "merge", **result}


class RerunReq(BaseModel):
    model: str = "opus"
    effort: Optional[str] = None


@app.post("/api/investigations/{inv_id}/rerun")
async def rerun(inv_id: str, req: RerunReq = RerunReq(), user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    _require_quota_available()
    with gs.conn() as c:
        row = c.execute("SELECT seed_type, seed_value FROM investigations WHERE id=?", (inv_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    model = _check_model(user_id, req.model)
    # A rerun may change the thinking-effort level; persist it so _build_env
    # applies the new choice to every phase of the fresh run.
    gs.set_effort(inv_id, _check_effort(req.effort))
    gs.clear_investigation(inv_id)
    with gs.conn() as c:
        c.execute("UPDATE investigations SET status='running' WHERE id=?", (inv_id,))
    asyncio.create_task(run_investigation(inv_id, row["seed_type"], row["seed_value"], model=model))
    return {"ok": True}


class EnrichReq(BaseModel):
    seed_type: str
    seed_value: str
    model: str = "opus"
    effort: Optional[str] = None


class AddSeedReq(BaseModel):
    seed_type: str = "auto"
    seed_value: str
    model: str = "opus"
    effort: Optional[str] = None


@app.post("/api/investigations/{inv_id}/add_seed")
async def add_seed(inv_id: str, req: AddSeedReq, user_id: int = Depends(current_user)):
    """Add a NEW PEER seed to an existing investigation.

    Unlike /enrich (which frames the new IOC as a pivot descendant of an existing
    graph node), add_seed treats the new IOC as an independent peer. The agent
    runs the full single-seed workflow on it and only links to prior seeds when
    concrete shared infrastructure is observed. Shared infra becomes cross-seed
    links automatically via the (inv,type,value) upsert in add_node.
    """
    _require_owner(inv_id, user_id)
    _require_quota_available()
    seed_type = req.seed_type if req.seed_type != "auto" else detect_seed_type(req.seed_value)
    if seed_type not in ALLOWED_SEED_TYPES:
        raise HTTPException(status_code=400, detail=f"unknown seed_type: {seed_type}")
    sv = _clean_seed(seed_type, req.seed_value)
    if not sv:
        raise HTTPException(status_code=400, detail="seed_value required")
    model = _check_model(user_id, req.model)
    gs.set_effort(inv_id, _check_effort(req.effort))
    gs.set_status(inv_id, "running")
    import json as _json, time as _time
    with gs.conn() as c:
        payload = {"kind": "status_change", "status": "running",
                   "add_seed_type": seed_type, "add_seed_value": sv}
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv_id, "status_change", _json.dumps(payload), _time.time()))
    asyncio.create_task(run_add_seed(inv_id, seed_type, sv, model=model))
    return {"ok": True}


@app.post("/api/investigations/{inv_id}/enrich")
async def enrich(inv_id: str, req: EnrichReq, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    _require_quota_available()
    if req.seed_type not in ALLOWED_SEED_TYPES:
        raise HTTPException(status_code=400, detail=f"unknown seed_type: {req.seed_type}")
    sv = _clean_seed(req.seed_type, req.seed_value)
    if not sv:
        raise HTTPException(status_code=400, detail="seed_value required")
    model = _check_model(user_id, req.model)
    gs.set_effort(inv_id, _check_effort(req.effort))
    gs.set_status(inv_id, "running")
    # Emit a status_change event so any connected WebSocket clients can refresh
    # the sidebar status live (otherwise the sidebar keeps showing "done" while
    # the pivot is actively writing new nodes).
    import json as _json, time as _time
    with gs.conn() as c:
        payload = {"kind": "status_change", "status": "running",
                   "pivot_seed_type": req.seed_type, "pivot_seed_value": sv}
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv_id, "status_change", _json.dumps(payload), _time.time()))
    asyncio.create_task(run_pivot(inv_id, req.seed_type, sv, model=model))
    return {"ok": True}


class SelectedNode(BaseModel):
    type: str
    value: str


class CustomPromptReq(BaseModel):
    prompt: str
    model: str = "opus"
    effort: Optional[str] = None
    selected_nodes: Optional[list[SelectedNode]] = None


@app.post("/api/investigations/{inv_id}/prompt")
async def custom_prompt(inv_id: str, req: CustomPromptReq, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    _require_quota_available()
    prompt_text = (req.prompt or "").strip()
    if not prompt_text:
        raise HTTPException(status_code=400, detail="prompt required")
    model = _check_model(user_id, req.model)
    gs.set_effort(inv_id, _check_effort(req.effort))
    gs.set_status(inv_id, "running")
    import json as _json, time as _time
    with gs.conn() as c:
        payload = {"kind": "status_change", "status": "running",
                   "custom_prompt": prompt_text[:200]}
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv_id, "status_change", _json.dumps(payload), _time.time()))
    sel = [{"type": n.type, "value": n.value} for n in req.selected_nodes] if req.selected_nodes else None
    asyncio.create_task(run_custom_prompt(inv_id, prompt_text, model=model, selected_nodes=sel))
    return {"ok": True}


@app.get("/api/investigations/{inv_id}/pdf")
def export_pdf(inv_id: str, user_id: int = Depends(current_user)):
    """Generate and return a PDF report for the investigation."""
    _require_owner(inv_id, user_id)
    try:
        from .pdf_report import generate_pdf
        pdf_bytes = generate_pdf(inv_id)
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"PDF generation unavailable (missing fpdf2?): {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="bounce-cti-{inv_id}.pdf"'},
    )


@app.get("/api/investigations/{inv_id}/stix")
def export_stix(inv_id: str, user_id: int = Depends(current_user)):
    """Generate and return a STIX 2.1 bundle for the investigation."""
    _require_owner(inv_id, user_id)
    try:
        from .stix_export import generate_stix_bundle
        bundle = generate_stix_bundle(inv_id)
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"STIX export unavailable: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"STIX export failed: {e}")
    import json
    content = json.dumps(bundle, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="bounce-cti-{inv_id}.stix.json"'},
    )


@app.get("/api/investigations/{inv_id}/csv")
def export_csv(inv_id: str, user_id: int = Depends(current_user)):
    """Generate and return a STIX-flavoured CSV of observables for the
    investigation, ready to feed into an OpenCTI workbench via its CSV
    mapper. Columns include `stix_type` / `entity_type`, hashes split per
    algorithm, labels, sources, and a short description."""
    _require_owner(inv_id, user_id)
    try:
        from .stix_export import generate_csv
        content = generate_csv(inv_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV export failed: {e}")
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="bounce-cti-{inv_id}.observables.csv"'},
    )


@app.get("/api/investigations/{inv_id}/actions/blocklist")
def export_blocklist(inv_id: str, fmt: str = "plain",
                      include_defused: bool = False,
                      user_id: int = Depends(current_user)):
    """Render the investigation's network IOCs as a blocklist artefact.

    ``fmt`` is one of ``plain | hosts | unbound | rpz | palo_edl |
    cisco_acl | csv``. Defused nodes (CDN/parking/sinkhole/Tor/…) are
    excluded by default — flip ``include_defused`` if the analyst has
    audited that the indicator is genuinely malicious despite the tag."""
    _require_owner(inv_id, user_id)
    try:
        from . import action_exports as ax
        g = gs.get_graph(inv_id)
        content = ax.render_blocklist(g["nodes"], fmt, include_defused=include_defused)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"blocklist render failed: {e}")
    return {"format": fmt, "content": content,
            "filename": f"bounce-cti-{inv_id}.blocklist.{fmt}.txt"}


@app.get("/api/investigations/{inv_id}/actions/detection")
def export_detection(inv_id: str, fmt: str = "sigma",
                      include_defused: bool = False,
                      user_id: int = Depends(current_user)):
    """Render a starter detection rule (Sigma / Snort / YARA) from the
    investigation's IOCs. Output is a starting point — the defender must
    tune false positives and add environment context before deploying."""
    _require_owner(inv_id, user_id)
    try:
        from . import action_exports as ax
        g = gs.get_graph(inv_id)
        content = ax.render_detection(g["nodes"], fmt,
                                       investigation_id=inv_id,
                                       include_defused=include_defused)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"detection render failed: {e}")
    suffix = {"sigma": "yml", "snort": "rules", "yara": "yar"}.get(fmt, "txt")
    return {"format": fmt, "content": content,
            "filename": f"bounce-cti-{inv_id}.detection.{fmt}.{suffix}"}


@app.get("/api/investigations/{inv_id}/actions/takedown")
def export_takedown(inv_id: str, user_id: int = Depends(current_user)):
    """Render a list of takedown-ready abuse-email bundles, one per
    malicious host/IP with a known abuse contact. The analyst still owns
    the send — bounce-cti never auto-emails anyone."""
    _require_owner(inv_id, user_id)
    try:
        from . import action_exports as ax
        g = gs.get_graph(inv_id)
        bundles = ax.render_takedown(g["nodes"], g["edges"],
                                       investigation_id=inv_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"takedown render failed: {e}")
    return {"count": len(bundles), "items": bundles}


@app.get("/api/investigations/{inv_id}/nodes/{node_id}/evidence")
def node_evidence(inv_id: str, node_id: str, user_id: int = Depends(current_user)):
    """Return raw cached CTI source data relevant to a node.

    Lets the analyst audit what each source actually returned, so they can
    verify the LLM summary didn't omit anything.
    """
    _require_owner(inv_id, user_id)
    node = gs.get_node_by_id(inv_id, node_id)
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    evidence = gs.get_evidence_for_value(node["value"])
    return {"node_id": node_id, "value": node["value"], "evidence": evidence}


# ── Node annotations (pin tag + free-text note) ──────────────────────────
class TagToggleReq(BaseModel):
    tag: str
    on: bool = True


@app.post("/api/investigations/{inv_id}/nodes/{node_id}/tag")
def toggle_node_tag(inv_id: str, node_id: str, req: TagToggleReq,
                    user_id: int = Depends(current_user)):
    """Add or remove a single tag on a node. Used for the Pin button
    (tag='pinned'), but generic — any tag works. Persists + broadcasts
    a node_updated event so other open clients see the change live."""
    _require_owner(inv_id, user_id)
    tag = (req.tag or "").strip().lower()[:32]
    if not tag:
        raise HTTPException(status_code=400, detail="tag required")
    node = gs.set_node_tag(inv_id, node_id, tag, bool(req.on))
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    return {"node": node}


class NoteReq(BaseModel):
    note: str = ""


@app.post("/api/investigations/{inv_id}/nodes/{node_id}/note")
def set_node_note(inv_id: str, node_id: str, req: NoteReq,
                  user_id: int = Depends(current_user)):
    """Set or clear an analyst's free-text annotation on a node
    (e.g. 'VPN server', 'C2', 'sinkhole'). Stored in metadata.user_note.
    Empty string clears."""
    _require_owner(inv_id, user_id)
    node = gs.set_node_user_note(inv_id, node_id, req.note or "")
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    return {"node": node}


# ── Bootstrap from a CTI PDF ────────────────────────────────────────────────
# Lets an analyst upload an existing report (vendor write-up, IR debrief, …)
# and get a graph for free: server-side regex pulls every plausible IOC out
# of the text, refangs them, and chains them as seeds on a single combined
# investigation. Same end result as running the equivalent batch-combined
# flow by hand — minus the typing.
PDF_MAX_BYTES = 25 * 1024 * 1024  # 25 MB ceiling
PDF_MAX_SEEDS = 10                # cap so one PDF can't blow the rate-limits


def _read_pdf_iocs(file: UploadFile) -> tuple[list[dict], str, bytes]:
    """Slurp the upload, parse, and return (iocs, text, raw_bytes).
    Raises HTTPException for any client-facing failure so the caller stays small."""
    fname = (file.filename or "").lower()
    if not fname.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="must be a .pdf file")
    blob = file.file.read()
    if len(blob) > PDF_MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"file too large (>{PDF_MAX_BYTES // (1024*1024)} MB)")
    if len(blob) < 32:
        raise HTTPException(status_code=400, detail="empty file")
    try:
        from . import pdf_import as pi
        text = pi.extract_text(blob)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"could not parse PDF: {e}")
    if not text.strip():
        raise HTTPException(status_code=422, detail="no extractable text in this PDF (image-only scan?)")
    iocs = pi.extract_iocs(text)
    if not iocs:
        raise HTTPException(status_code=422, detail="no IOCs found in this PDF")
    return iocs, text, blob


@app.post("/api/investigations/from_pdf")
async def from_pdf(
    file: UploadFile = File(...),
    model: str = Form("sonnet"),
    effort: str = Form(default=""),
    user_id: int = Depends(current_user),
):
    """Spin up a fresh investigation seeded from a CTI report PDF."""
    _require_quota_available()
    model = _check_model(user_id, model)
    effort = _check_effort(effort)
    iocs, text, _blob = _read_pdf_iocs(file)
    seeds = iocs[:PDF_MAX_SEEDS]
    primary = seeds[0]
    extras = seeds[1:]
    inv_id = gs.create_investigation(primary["type"], primary["value"], user_id=user_id, model=model, effort=effort)
    # Stash the source text so the agent (and the UI later) can read what
    # the analyst actually uploaded — keyed by inv_id, capped to keep the
    # cache table small.
    gs.cache_set(f"pdf_source:{inv_id}", {
        "filename": file.filename,
        "text_excerpt": text[:50_000],
        "extracted_iocs": iocs,
        "uploaded_at": time.time(),
    })

    async def _chain():
        import json as _json
        # First pass gets the full report text so the agent encodes the
        # narrative (actors, campaigns, stated relationships) into the graph.
        # Subsequent add-seed passes don't need the text — the graph already
        # carries those nodes and tags.
        await run_investigation(
            inv_id, primary["type"], primary["value"], model=model,
            report_context=text,
        )
        for it in extras:
            gs.set_status(inv_id, "running")
            with gs.conn() as c:
                payload = {"kind": "status_change", "status": "running",
                           "add_seed_type": it["type"], "add_seed_value": it["value"]}
                c.execute(
                    "INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                    (inv_id, "status_change", _json.dumps(payload), time.time()),
                )
            await run_add_seed(inv_id, it["type"], it["value"], model=model)

    asyncio.create_task(_chain())
    return {
        "id": inv_id,
        "filename": file.filename,
        "extracted_iocs": iocs,
        "seeds_queued": len(seeds),
    }


@app.post("/api/investigations/{inv_id}/from_pdf")
async def add_pdf_seeds(
    inv_id: str,
    file: UploadFile = File(...),
    model: str = Form("sonnet"),
    user_id: int = Depends(current_user),
):
    """Append IOCs from a CTI report into an existing investigation as
    add-seed pivots — useful when an analyst is mid-investigation and a
    fresh write-up lands."""
    _require_owner(inv_id, user_id)
    _require_quota_available()
    model = _check_model(user_id, model)
    iocs, text, _blob = _read_pdf_iocs(file)
    seeds = iocs[:PDF_MAX_SEEDS]
    # Keep an audit trail for this PDF too (overwrite-safe key namespacing
    # prevents collision with the original from_pdf bootstrap).
    gs.cache_set(f"pdf_source:{inv_id}:{int(time.time())}", {
        "filename": file.filename,
        "text_excerpt": text[:50_000],
        "extracted_iocs": iocs,
        "uploaded_at": time.time(),
    })

    async def _chain():
        import json as _json
        for it in seeds:
            gs.set_status(inv_id, "running")
            with gs.conn() as c:
                payload = {"kind": "status_change", "status": "running",
                           "add_seed_type": it["type"], "add_seed_value": it["value"]}
                c.execute(
                    "INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                    (inv_id, "status_change", _json.dumps(payload), time.time()),
                )
            await run_add_seed(inv_id, it["type"], it["value"], model=model)

    asyncio.create_task(_chain())
    return {
        "id": inv_id,
        "filename": file.filename,
        "extracted_iocs": iocs,
        "seeds_queued": len(seeds),
    }


# ── Sample / command-line import ──────────────────────────────────────────
# Accepts either a binary upload (malware.exe, dropper script, archive…) or
# a pasted command line / script. Hashes binaries (the hash becomes the seed
# IOC), extracts IOCs from scripts (each becomes an add-seed), and creates a
# command_line context node so the agent reads the raw text via report_context.

@app.post("/api/investigations/from_sample")
async def from_sample(
    file: UploadFile | None = File(default=None),
    text: str = Form(default=""),
    model: str = Form("sonnet"),
    effort: str = Form(default=""),
    user_id: int = Depends(current_user),
):
    """Spin up a fresh investigation from a malware sample upload OR a
    pasted command line / script.

    Provide EXACTLY ONE of:
      - `file`: any uploaded binary or text file (executable, dropper, script…)
      - `text`: a pasted command line or script snippet
    """
    _require_quota_available()
    model = _check_model(user_id, model)
    effort = _check_effort(effort)
    from . import sample_import as si

    blob: bytes | None = None
    filename: str | None = None
    if file is not None and (file.filename or ""):
        blob = file.file.read()
        filename = file.filename
        if len(blob) > si.SAMPLE_MAX_BYTES:
            raise HTTPException(status_code=413,
                detail=f"file too large (>{si.SAMPLE_MAX_BYTES // (1024*1024)} MB)")
        if len(blob) == 0:
            raise HTTPException(status_code=400, detail="empty file")

    if (blob is None or len(blob) == 0) and not text.strip():
        raise HTTPException(status_code=400,
            detail="provide either a file upload or a non-empty `text` field")
    if blob is not None and text.strip():
        # Avoid implicit precedence rules — refuse instead of guessing.
        raise HTTPException(status_code=400,
            detail="provide EITHER a file OR text, not both")

    try:
        result = si.handle_file_upload(blob, filename) if blob is not None \
                 else si.handle_text_paste(text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    primary = result["primary"]
    extras  = result["extras"][:si.SAMPLE_MAX_SEEDS - 1]   # primary counts
    context_node = result["context_node"]
    report_text  = result["report_text"]
    hashes       = result["hashes"]

    inv_id = gs.create_investigation(primary["type"], primary["value"],
                                     user_id=user_id, model=model, effort=effort)
    # Stamp the seed node with the rich metadata up-front so the UI shows the
    # original filename / sha1 / md5 BEFORE the agent fires.
    gs.add_node(inv_id, primary["type"], primary["value"],
                metadata=primary.get("metadata") or {}, source="user", tags=["seed"])
    # Pre-register the command_line context node when we have one. The agent
    # also receives the raw text via report_context, but graphing it now means
    # the UI shows it immediately and embedded_in_command edges have a target.
    if context_node:
        gs.add_node(inv_id, context_node["type"], context_node["value"],
                    metadata=context_node.get("metadata") or {},
                    source="user", tags=["seed_context"])

    # Audit trail (mirrors what from_pdf does).
    gs.cache_set(f"sample_source:{inv_id}", {
        "filename": filename,
        "file_type": result["file_type"],
        "hashes": hashes,
        "extracted_iocs": [primary] + extras,
        "text_excerpt": (report_text or "")[:50_000],
        "uploaded_at": time.time(),
    })

    async def _chain():
        import json as _json
        await run_investigation(
            inv_id, primary["type"], primary["value"], model=model,
            report_context=report_text or "",
        )
        for it in extras:
            gs.set_status(inv_id, "running")
            with gs.conn() as c:
                payload = {"kind": "status_change", "status": "running",
                           "add_seed_type": it["type"], "add_seed_value": it["value"]}
                c.execute(
                    "INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                    (inv_id, "status_change", _json.dumps(payload), time.time()),
                )
            await run_add_seed(inv_id, it["type"], it["value"], model=model)

    asyncio.create_task(_chain())
    return {
        "id": inv_id,
        "filename": filename,
        "file_type": result["file_type"],
        "hashes": hashes,
        "primary": {"type": primary["type"], "value": primary["value"]},
        "extracted_iocs": extras,
        "seeds_queued": 1 + len(extras),
    }


# ── Sharing ────────────────────────────────────────────────────────────────
class CreateShareReq(BaseModel):
    sections: Optional[list[str]] = None  # subset of SHARE_SECTIONS
    expires_in_days: Optional[int] = None
    label: Optional[str] = None


@app.post("/api/investigations/{inv_id}/shares")
def create_share(inv_id: str, req: CreateShareReq, request: Request,
                 user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    expires_at = None
    if req.expires_in_days and req.expires_in_days > 0:
        expires_at = time.time() + req.expires_in_days * 86400
    sh = gs.create_share(inv_id, user_id, req.sections or [], expires_at=expires_at,
                         label=(req.label or None))
    base = str(request.base_url).rstrip("/")
    sh["url"] = f"{base}/?share={sh['token']}"
    return sh


@app.get("/api/investigations/{inv_id}/shares")
def list_inv_shares(inv_id: str, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    return gs.list_shares_for_investigation(inv_id)


@app.get("/api/shares")
def list_my_shares(user_id: int = Depends(current_user)):
    return gs.list_shares_for_user(user_id)


@app.delete("/api/shares/{token}")
def delete_share(token: str, user_id: int = Depends(current_user)):
    ok = gs.delete_share(token, user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="not found")
    return {"ok": True}


@app.post("/api/shares/{token}/revoke")
def revoke_share(token: str, user_id: int = Depends(current_user)):
    ok = gs.revoke_share(token, user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="not found")
    return {"ok": True}


@app.get("/api/share/{token}")
def get_public_share(token: str):
    """Public endpoint — no auth. Returns the filtered investigation payload
    (graph + opt-in sections) so an analyst can review a colleague's graph
    by URL alone. Revoked / expired tokens 404."""
    payload = gs.get_share_payload(token)
    if payload is None:
        raise HTTPException(status_code=404, detail="share not found, revoked, or expired")
    return payload


class ImportShareReq(BaseModel):
    target_inv_id: Optional[str] = None  # when set, merge into this inv instead of cloning


@app.post("/api/share/{token}/import")
def import_share(token: str,
                 req: Optional[ImportShareReq] = None,
                 user_id: int = Depends(current_user)):
    """Add the shared graph to the caller's investigations.

    Two modes:
    - `target_inv_id` omitted: clone — creates a brand-new investigation
      owned by the caller (status='done'), node ids recomputed against
      the new inv. This is the default when the recipient has no graph
      to merge into.
    - `target_inv_id` provided and owned by the caller: merge — upserts
      every shared node into the existing investigation (dedup by
      type/value, metadata + tags + sources_seen unioned) and rewrites
      edges against the target. Existing report node is preserved.

    Either way, sections follow the share's filter (chats excluded if
    the link excluded them).
    """
    s = gs.get_share(token)
    if not s or s["revoked"]:
        raise HTTPException(status_code=404, detail="share not found")
    if s["expires_at"] and s["expires_at"] < time.time():
        raise HTTPException(status_code=410, detail="share expired")

    target = (req.target_inv_id if req else None)
    if target:
        if gs.get_investigation_owner(target) != user_id:
            raise HTTPException(status_code=403, detail="target investigation not owned by you")
        result = gs.merge_into_investigation(s["investigation_id"], target, sections=s["sections"])
        # Echo the same shape as clone (`id`) so the UI can open the inv
        # uniformly, alongside the merge counters.
        return {"id": target, "mode": "merge", **result}

    new_id = gs.clone_investigation(s["investigation_id"], user_id, sections=s["sections"])
    if not new_id:
        raise HTTPException(status_code=404, detail="source investigation missing")
    return {"id": new_id, "mode": "clone"}


@app.websocket("/ws/{inv_id}")
async def ws(websocket: WebSocket, inv_id: str):
    # Auth via session cookie; close before accept() if not authenticated.
    token = websocket.cookies.get(SESSION_COOKIE)
    user_id = auth.resolve_session(token)
    if user_id is None:
        await websocket.close(code=4401)
        return
    if gs.get_investigation_owner(inv_id) != user_id:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    _active_ws.add(websocket)
    last = 0
    await websocket.send_json({"kind": "snapshot", "graph": gs.get_graph(inv_id)})
    try:
        while True:
            events = gs.get_events_since(inv_id, last)
            for e in events:
                last = max(last, e.get("_id", last))
                await websocket.send_json(e)
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return
    finally:
        _active_ws.discard(websocket)


# Serve frontend build if present
DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if DIST.exists():
    app.mount("/", StaticFiles(directory=str(DIST), html=True), name="frontend")
