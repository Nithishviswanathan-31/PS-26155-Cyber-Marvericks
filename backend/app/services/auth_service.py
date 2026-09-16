import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import time

from fastapi import Depends, Request
from ..config import AUTH_REQUIRED, AUTH_SECRET, AUTH_TTL_SECONDS
from ..domain.auth import Role
from ..storage import auth as store


class AuthError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
    return "pbkdf2_sha256$600000$" + base64.b64encode(salt + digest).decode()


def verify(password: str, stored: str) -> bool:
    try:
        # Retain compatibility with the initial primitive's 310000-iteration format.
        if stored.startswith("pbkdf2_sha256$600000$"):
            raw = base64.b64decode(stored.split("$")[2], validate=True)
            rounds = 600000
        else:
            raw = base64.b64decode(stored, validate=True)
            rounds = 310000
        return len(raw) == 48 and hmac.compare_digest(
            hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], rounds), raw[16:])
    except (ValueError, TypeError):
        return False


def validate_settings():
    production = os.getenv("APP_ENV", "development").lower() in {"production", "prod"}
    if production and not AUTH_REQUIRED:
        raise RuntimeError("Production requires AUTH_REQUIRED=true")
    if AUTH_REQUIRED and (len(AUTH_SECRET.encode()) < 32 or not 60 <= AUTH_TTL_SECONDS <= 86400):
        raise RuntimeError("Configure AUTH_SECRET (at least 32 bytes) and AUTH_TTL_SECONDS (60..86400)")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def token(user: dict) -> str:
    if len(AUTH_SECRET.encode()) < 32:
        raise AuthError(503, "AUTH_NOT_CONFIGURED", "Authentication is not configured.")
    expiry = time.time() + AUTH_TTL_SECONDS
    body = base64.urlsafe_b64encode(json.dumps({"id": user["user_id"], "exp": expiry, "jti": secrets.token_urlsafe(32)}).encode()).decode()
    signature = hmac.new(AUTH_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    value = f"{body}.{signature}"
    with store.connection() as db:
        # Login and concurrent disable/password changes cannot resurrect access.
        db.execute("BEGIN IMMEDIATE")
        current = db.execute("SELECT * FROM users WHERE user_id=?", (user["user_id"],)).fetchone()
        if not current or not current["active"] or current["updated_at"] != user["updated_at"]:
            raise AuthError(401, "INVALID_CREDENTIALS", "Invalid credentials.")
        db.execute("INSERT INTO auth_sessions VALUES (?,?,?,0)", (fingerprint(value), user["user_id"], expiry))
        store.event(db, user, "LOGIN", user["user_id"])
    return value


def actor(request: Request):
    authorization = request.headers.get("authorization")
    if not authorization and not AUTH_REQUIRED:
        return {"user_id": "legacy-demo", "username": "legacy-demo", "display_name": "Local demo (authentication disabled)", "role": "ADMIN", "offline": True}
    try:
        if not authorization or not authorization.startswith("Bearer ") or len(authorization) > 4096 or len(AUTH_SECRET.encode()) < 32:
            raise ValueError()
        value = authorization[7:]
        body, signature = value.rsplit(".", 1)
        expected = hmac.new(AUTH_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError()
        data = json.loads(base64.urlsafe_b64decode(body))
        if (type(data["exp"]) not in (int, float) or not math.isfinite(data["exp"])
                or data["exp"] <= time.time() or not isinstance(data["id"], str)):
            raise ValueError()
        with store.connection() as db:
            session = db.execute("SELECT * FROM auth_sessions WHERE token_hash=?", (fingerprint(value),)).fetchone()
            if not session or session["revoked"] or session["expires_at"] <= time.time() or session["user_id"] != data["id"]:
                raise ValueError()
            row = db.execute("SELECT * FROM users WHERE user_id=? AND active=1", (session["user_id"],)).fetchone()
            if not row:
                raise ValueError()
            result = store.public(row)
        result["offline"] = False
        return result
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise AuthError(401, "UNAUTHENTICATED", "Authentication required or session invalid.") from None


def require(*roles: Role):
    def dependency(user=Depends(actor)):
        if user["role"] not in roles:
            raise AuthError(403, "FORBIDDEN", "Your role does not permit this operation.")
        return user
    return dependency


def administrator(user=Depends(require(Role.ADMIN))):
    # Offline audit compatibility must not become a public user-management bypass.
    if user.get("offline"):
        raise AuthError(401, "UNAUTHENTICATED", "Sign in as an administrator.")
    return user


# All existing mutations are enumerated. Any new mutation is denied until classified.
MUTATION_ROLES = {
    "analyze_configuration": {"ADMIN", "AUDITOR"},
    "analyze_batch": {"ADMIN", "AUDITOR"},
    "simulate_remediation": {"ADMIN", "AUDITOR"},
    "reanalyze_simulation": {"ADMIN", "AUDITOR", "REVIEWER"},
    "reanalyze_configuration": {"ADMIN", "AUDITOR", "REVIEWER"},
    "suggest_mapping": {"ADMIN", "REVIEWER"},
    "generate_interpretations": {"ADMIN", "REVIEWER"},
    "approve_mapping": {"ADMIN", "REVIEWER"},
    "correct_mapping": {"ADMIN", "REVIEWER"},
    "reject_mapping": {"ADMIN", "REVIEWER"},
    "deactivate_entry": {"ADMIN", "REVIEWER"},
    "verify": {"ADMIN", "AUDITOR", "REVIEWER"},
    "reset_demo": {"ADMIN"},
}


async def authorize_route(request: Request, user=Depends(actor)):
    request.state.actor = user
    mutation = request.method not in {"GET", "HEAD", "OPTIONS"}
    name = request.scope["route"].name
    if mutation and user["role"] not in MUTATION_ROLES.get(name, set()):
        raise AuthError(403, "FORBIDDEN", "Your role does not permit this operation.")
    if mutation and not user.get("offline"):
        with store.connection() as db:
            store.event(db, user, name + ":REQUESTED", request.url.path)
    try:
        yield
    except Exception:
        if mutation and not user.get("offline"):
            with store.connection() as db:
                store.event(db, user, name + ":FAILED", request.url.path)
        raise
    else:
        if mutation and not user.get("offline"):
            with store.connection() as db:
                store.event(db, user, name + ":COMPLETED", request.url.path)


def reviewer_identity(request: Request, legacy: str) -> str:
    user = request.state.actor
    return legacy if user.get("offline") else user["user_id"]
