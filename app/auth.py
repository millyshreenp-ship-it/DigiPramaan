"""Authentication, sessions and role checks.

* Passwords: scrypt with a per-user random salt. Minimum 10 characters.
* Sessions: random 256-bit token in an HttpOnly, SameSite=Strict cookie. Only a SHA-256 of the token is stored server-side.
* CSRF: every state-changing /api request must carry the header X-Requested-With: idff (enforced in main.py middleware;
  browsers cannot attach it cross-site without a CORS preflight, which this server never allows).
* Login throttling: 5 failures per username+IP per 15 minutes."""
import hashlib, hmac, os, secrets, time
from fastapi import Depends, HTTPException, Request
from . import config, db

ROLES = ("admin", "investigator", "examiner", "supervisor", "reviewer", "auditor")
COOKIE = "idff_session"
_failures: dict[tuple, list[float]] = {}

def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"

def check_password(pw: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
        new = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(new.hex(), dk)
    except Exception:
        return False

def validate_new_password(pw: str) -> None:
    if len(pw) < 10:
        raise HTTPException(400, "Password must be at least 10 characters.")

def throttled(key: tuple) -> bool:
    now = time.time()
    recent = [t for t in _failures.get(key, []) if now - t < config.LOGIN_WINDOW_SECONDS]
    _failures[key] = recent
    return len(recent) >= config.LOGIN_MAX_FAILURES

def note_failure(key: tuple) -> None:
    _failures.setdefault(key, []).append(time.time())

def clear_failures(key: tuple) -> None:
    _failures.pop(key, None)

def _tok_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def create_session(conn, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
    conn.execute("INSERT INTO sessions VALUES(?,?,?)", (_tok_hash(token), user_id, time.time() + config.SESSION_TTL_SECONDS))
    return token

def end_session(conn, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (_tok_hash(token),))

def end_user_sessions(conn, user_id: int) -> None:
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

def current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Sign in required.")
    with db.session() as c:
        r = c.execute("""SELECT u.user_id,u.username,u.full_name,u.role FROM sessions s JOIN users u ON u.user_id=s.user_id
                         WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""", (_tok_hash(token), time.time())).fetchone()
    if not r:
        raise HTTPException(401, "Session expired. Sign in again.")
    return dict(r)

def require(*roles: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        if roles and user["role"] not in roles:
            raise HTTPException(403, f"Your role ({user['role']}) is not permitted to do this.")
        return user
    return dep
