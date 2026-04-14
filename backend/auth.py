"""Lightweight PIN-based auth + admin bootstrap."""
import hmac
import hashlib
import json
import secrets
import time
from collections import defaultdict, deque
from typing import Optional

from . import graph_store as gs
from .config import DATA_DIR

SECRET_PATH = DATA_DIR / "secret.key"
PIN_LENGTH = 6
SESSION_TTL_SECONDS = 30 * 24 * 3600
RL_WINDOW_S = 15 * 60
RL_MAX = 5

_secret_cache: Optional[bytes] = None
_failed_attempts: dict[str, deque] = defaultdict(deque)


def _load_secret() -> bytes:
    global _secret_cache
    if _secret_cache is not None:
        return _secret_cache
    if SECRET_PATH.exists():
        _secret_cache = SECRET_PATH.read_bytes()
    else:
        _secret_cache = secrets.token_bytes(32)
        SECRET_PATH.write_bytes(_secret_cache)
        try:
            SECRET_PATH.chmod(0o600)
        except OSError:
            pass
    return _secret_cache


def pin_hmac(pin: str) -> str:
    return hmac.new(_load_secret(), pin.encode("utf-8"), hashlib.sha256).hexdigest()


def _gen_pin() -> str:
    return f"{secrets.randbelow(10 ** PIN_LENGTH):0{PIN_LENGTH}d}"


def create_user(allowed_models: Optional[list[str]] = None) -> tuple[int, str]:
    """Create a user with a freshly generated PIN and optional model whitelist.
    None/empty allowed_models means no restriction (all models OK)."""
    for _ in range(20):
        pin = _gen_pin()
        h = pin_hmac(pin)
        with gs.conn() as c:
            if c.execute("SELECT 1 FROM users WHERE pin_hmac=?", (h,)).fetchone():
                continue
            cur = c.execute(
                "INSERT INTO users(pin_hmac, created_at, is_admin, allowed_models) VALUES (?, ?, 0, ?)",
                (h, time.time(), json.dumps(allowed_models) if allowed_models else None),
            )
            return cur.lastrowid, pin
    raise RuntimeError("PIN collision after 20 tries")


def bootstrap_admin(pin: Optional[str]):
    """Ensure a user with this PIN exists and is flagged is_admin=1.
    Admin has no model restrictions (allowed_models=NULL). Idempotent."""
    if not pin:
        return
    pin = pin.strip()
    if not pin.isdigit() or len(pin) != PIN_LENGTH:
        return
    h = pin_hmac(pin)
    with gs.conn() as c:
        row = c.execute("SELECT id, is_admin FROM users WHERE pin_hmac=?", (h,)).fetchone()
        if row:
            if not row["is_admin"]:
                c.execute(
                    "UPDATE users SET is_admin=1, allowed_models=NULL WHERE id=?",
                    (row["id"],),
                )
        else:
            c.execute(
                "INSERT INTO users(pin_hmac, created_at, is_admin, allowed_models) VALUES (?, ?, 1, NULL)",
                (h, time.time()),
            )


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    dq = _failed_attempts[ip]
    while dq and dq[0] < now - RL_WINDOW_S:
        dq.popleft()
    return len(dq) >= RL_MAX


def _record_failure(ip: str):
    _failed_attempts[ip].append(time.time())


def _clear_failures(ip: str):
    _failed_attempts.pop(ip, None)


def verify_pin(pin: str, ip: str) -> Optional[int]:
    pin = (pin or "").strip()
    if not pin.isdigit() or len(pin) != PIN_LENGTH:
        _record_failure(ip)
        return None
    h = pin_hmac(pin)
    with gs.conn() as c:
        row = c.execute("SELECT id FROM users WHERE pin_hmac=?", (h,)).fetchone()
    if not row:
        _record_failure(ip)
        return None
    _clear_failures(ip)
    return row["id"]


def issue_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with gs.conn() as c:
        c.execute(
            "INSERT INTO sessions(token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, time.time() + SESSION_TTL_SECONDS),
        )
    return token


def resolve_session(token: Optional[str]) -> Optional[int]:
    if not token:
        return None
    with gs.conn() as c:
        row = c.execute(
            "SELECT user_id, expires_at FROM sessions WHERE token=?",
            (token,),
        ).fetchone()
    if not row:
        return None
    if row["expires_at"] < time.time():
        with gs.conn() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
        return None
    return row["user_id"]


def destroy_session(token: Optional[str]):
    if not token:
        return
    with gs.conn() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))


def get_user(user_id: int) -> Optional[dict]:
    """Return basic user info: {id, is_admin, allowed_models} or None."""
    with gs.conn() as c:
        row = c.execute(
            "SELECT id, is_admin, allowed_models FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
    if not row:
        return None
    allowed = json.loads(row["allowed_models"]) if row["allowed_models"] else None
    return {"id": row["id"], "is_admin": bool(row["is_admin"]), "allowed_models": allowed}
