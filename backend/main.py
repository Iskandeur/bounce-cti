"""FastAPI entry point: REST + WebSocket for live graph updates.

Auth: session cookie. All /api/* and /ws/* require it except /api/auth/login
and /api/auth/logout. Investigations are scoped to the authenticated user.

Admin (`is_admin=1`) can manage users via /api/admin/users and is not
restricted to any subset of models.
"""
import asyncio
import os
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

from . import graph_store as gs
from . import auth
from .agent_runner import run_investigation, run_pivot, run_add_seed, run_custom_prompt, stop_investigation
from .refang import refang

app = FastAPI(title="Bounce-CTI")
# Tight CORS: the frontend is served from the same origin as the API.
app.add_middleware(CORSMiddleware, allow_origins=[], allow_methods=["*"], allow_headers=["*"])


ALLOWED_MODELS = ["sonnet", "opus", "opus-4.7", "haiku"]
DEFAULT_MODEL = "opus"

SESSION_COOKIE = "session"


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
    return {"models": models, "default": default}


ALLOWED_SEED_TYPES = {"domain", "ip", "hash", "url", "jarm", "asn"}

import re

_RE_URL = re.compile(r"^(https?|ftp)://", re.I)
_RE_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_RE_IPV6 = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_RE_ASN = re.compile(r"^(asn?)\s*\d{1,10}$", re.I)
_RE_JARM = re.compile(r"^[0-9a-fA-F]{62}$")
_RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_RE_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_RE_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")
_RE_DOMAIN = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


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
    if _RE_JARM.match(v):
        return "jarm"
    if _RE_SHA256.match(v):
        return "hash"
    if _RE_SHA1.match(v):
        return "hash"
    if _RE_MD5.match(v):
        return "hash"
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
    return sv


class StartReq(BaseModel):
    seed_type: str = "auto"
    seed_value: str
    model: str = "opus"


@app.post("/api/investigations")
async def start(req: StartReq, user_id: int = Depends(current_user)):
    model = _check_model(user_id, req.model)
    seed_type = req.seed_type
    if seed_type == "auto":
        seed_type = detect_seed_type(req.seed_value)
    if seed_type not in ALLOWED_SEED_TYPES:
        raise HTTPException(status_code=400, detail=f"unknown seed_type: {seed_type}")
    sv = _clean_seed(seed_type, req.seed_value)
    if not sv:
        raise HTTPException(status_code=400, detail="seed_value required")
    inv_id = gs.create_investigation(seed_type, sv, user_id=user_id, model=model)
    asyncio.create_task(run_investigation(inv_id, seed_type, sv, model=model))
    return {"id": inv_id, "seed_type": seed_type}


class BatchItem(BaseModel):
    seed_type: str = "auto"
    seed_value: str


class BatchStartReq(BaseModel):
    items: list[BatchItem]
    model: str = "opus"
    combined: bool = False  # True → all IOCs on a single investigation graph


@app.post("/api/investigations/batch")
async def start_batch(req: BatchStartReq, user_id: int = Depends(current_user)):
    """Kick off many investigations at once.

    When `combined=false` (default): one investigation per IOC (parallel).
    When `combined=true`: one investigation seeded from the first IOC,
    then each additional IOC is launched as a pivot on that same graph
    so the agent can find cross-IOC links.
    """
    model = _check_model(user_id, req.model)
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
        inv_id = gs.create_investigation(st0, sv0, user_id=user_id, model=model)
        extra_seeds = valid[1:]

        async def _combined_chain(_iid=inv_id, _primary=(st0, sv0), _extras=extra_seeds):
            import json as _json, time as _time
            await run_investigation(_iid, _primary[0], _primary[1], model=model)
            for _st, _sv in _extras:
                gs.set_status(_iid, "running")
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
            inv_id = gs.create_investigation(st, sv, user_id=user_id, model=model)
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


class RerunReq(BaseModel):
    model: str = "opus"


@app.post("/api/investigations/{inv_id}/rerun")
async def rerun(inv_id: str, req: RerunReq = RerunReq(), user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    with gs.conn() as c:
        row = c.execute("SELECT seed_type, seed_value FROM investigations WHERE id=?", (inv_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    model = _check_model(user_id, req.model)
    gs.clear_investigation(inv_id)
    with gs.conn() as c:
        c.execute("UPDATE investigations SET status='running' WHERE id=?", (inv_id,))
    asyncio.create_task(run_investigation(inv_id, row["seed_type"], row["seed_value"], model=model))
    return {"ok": True}


class EnrichReq(BaseModel):
    seed_type: str
    seed_value: str
    model: str = "opus"


class AddSeedReq(BaseModel):
    seed_type: str = "auto"
    seed_value: str
    model: str = "opus"


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
    seed_type = req.seed_type if req.seed_type != "auto" else detect_seed_type(req.seed_value)
    if seed_type not in ALLOWED_SEED_TYPES:
        raise HTTPException(status_code=400, detail=f"unknown seed_type: {seed_type}")
    sv = _clean_seed(seed_type, req.seed_value)
    if not sv:
        raise HTTPException(status_code=400, detail="seed_value required")
    model = _check_model(user_id, req.model)
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
    if req.seed_type not in ALLOWED_SEED_TYPES:
        raise HTTPException(status_code=400, detail=f"unknown seed_type: {req.seed_type}")
    sv = _clean_seed(req.seed_type, req.seed_value)
    if not sv:
        raise HTTPException(status_code=400, detail="seed_value required")
    model = _check_model(user_id, req.model)
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
    selected_nodes: Optional[list[SelectedNode]] = None


@app.post("/api/investigations/{inv_id}/prompt")
async def custom_prompt(inv_id: str, req: CustomPromptReq, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    prompt_text = (req.prompt or "").strip()
    if not prompt_text:
        raise HTTPException(status_code=400, detail="prompt required")
    model = _check_model(user_id, req.model)
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
