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
from .agent_runner import run_investigation, run_pivot

app = FastAPI(title="Bounce-CTI")
# Tight CORS: the frontend is served from the same origin as the API.
app.add_middleware(CORSMiddleware, allow_origins=[], allow_methods=["*"], allow_headers=["*"])


ALLOWED_MODELS = ["sonnet", "opus", "haiku",
                  "claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"]
DEFAULT_MODEL = "opus"

SESSION_COOKIE = "session"


# ── Startup: ensure admin PIN exists ───────────────────────────────────────
@app.on_event("startup")
def _bootstrap():
    auth.bootstrap_admin(os.getenv("ADMIN_PIN"))


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
    uid, pin = auth.create_user(allowed_models=allowed)
    return {"id": uid, "pin": pin}


class UpdateUserReq(BaseModel):
    allowed_models: Optional[list[str]] = None  # None/[] → unrestricted


@app.patch("/api/admin/users/{target_id}")
def admin_update_user(target_id: int, req: UpdateUserReq, _: int = Depends(current_admin)):
    allowed = req.allowed_models or None
    if allowed:
        bad = [m for m in allowed if m not in ALLOWED_MODELS]
        if bad:
            raise HTTPException(status_code=400, detail=f"unknown models: {bad}")
    gs.update_user_allowed_models(target_id, allowed)
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


class StartReq(BaseModel):
    seed_type: str
    seed_value: str
    model: str = "opus"


@app.post("/api/investigations")
async def start(req: StartReq, user_id: int = Depends(current_user)):
    model = _check_model(user_id, req.model)
    inv_id = gs.create_investigation(req.seed_type, req.seed_value, user_id=user_id)
    asyncio.create_task(run_investigation(inv_id, req.seed_type, req.seed_value, model=model))
    return {"id": inv_id}


@app.get("/api/investigations")
def list_inv(user_id: int = Depends(current_user)):
    return gs.list_investigations(user_id=user_id)


@app.get("/api/investigations/{inv_id}/graph")
def graph(inv_id: str, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    return gs.get_graph(inv_id)


@app.delete("/api/investigations/{inv_id}")
def delete_inv(inv_id: str, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
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


@app.post("/api/investigations/{inv_id}/enrich")
async def enrich(inv_id: str, req: EnrichReq, user_id: int = Depends(current_user)):
    _require_owner(inv_id, user_id)
    model = _check_model(user_id, req.model)
    gs.set_status(inv_id, "running")
    # Emit a status_change event so any connected WebSocket clients can refresh
    # the sidebar status live (otherwise the sidebar keeps showing "done" while
    # the pivot is actively writing new nodes).
    import json as _json, time as _time
    with gs.conn() as c:
        payload = {"kind": "status_change", "status": "running",
                   "pivot_seed_type": req.seed_type, "pivot_seed_value": req.seed_value}
        c.execute("INSERT INTO events(investigation_id, kind, payload, created_at) VALUES (?,?,?,?)",
                  (inv_id, "status_change", _json.dumps(payload), _time.time()))
    asyncio.create_task(run_pivot(inv_id, req.seed_type, req.seed_value, model=model))
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


# Serve frontend build if present
DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if DIST.exists():
    app.mount("/", StaticFiles(directory=str(DIST), html=True), name="frontend")
