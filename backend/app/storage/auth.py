"""Additive security tables; demo-data reset deliberately preserves these records."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import sqlite3
from uuid import uuid4

from ..config import DATABASE_PATH
from ..domain.auth import User, UserCreateRequest, UserUpdateRequest
from .database import get_connection


def now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection():
    db = get_connection(DATABASE_PATH)
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize():
    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMIN','AUDITOR','REVIEWER')),
            active INTEGER NOT NULL CHECK(active IN (0,1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS auth_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
            role TEXT NOT NULL, action TEXT NOT NULL, target TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS login_limits (
            login_key TEXT PRIMARY KEY, attempts INTEGER NOT NULL, window_start REAL NOT NULL);
        """)


def public(row):
    return User.model_validate(dict(row)).model_dump(mode="json")


def event(db, actor, action, target=None):
    db.execute("INSERT INTO auth_events(user_id,role,action,target,created_at) VALUES (?,?,?,?,?)",
               (actor["user_id"], actor["role"], action, target, now()))


def create(request: UserCreateRequest, actor):
    from ..services.auth_service import hash_password, AuthError
    stamp = now()
    uid = str(uuid4())
    password_hash = hash_password(request.password)
    try:
        with connection() as db:
            db.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)", (
                uid, request.username, request.display_name, password_hash, request.role.value, 1, stamp, stamp))
            event(db, actor, "USER_CREATE", uid)
            return public(db.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone())
    except sqlite3.IntegrityError:
        raise AuthError(409, "USER_CONFLICT", "Username is already in use.") from None


def update(uid: str, request: UserUpdateRequest, actor):
    from ..services.auth_service import hash_password, AuthError
    changes = request.model_dump(exclude_unset=True)
    if not changes or any(value is None for value in changes.values()):
        raise AuthError(422, "VALIDATION_ERROR", "Supply non-null user changes.")
    password_hash = hash_password(request.password) if request.password else None
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone()
        if row is None:
            raise AuthError(404, "USER_NOT_FOUND", "User was not found.")
        role = request.role.value if request.role else row["role"]
        active = request.active if request.active is not None else bool(row["active"])
        if row["role"] == "ADMIN" and row["active"] and (role != "ADMIN" or not active):
            count = db.execute("SELECT COUNT(*) FROM users WHERE role='ADMIN' AND active=1").fetchone()[0]
            if count <= 1:
                raise AuthError(409, "FINAL_ADMIN", "The final enabled administrator must remain usable.")
        db.execute("UPDATE users SET role=?,active=?,password_hash=?,updated_at=? WHERE user_id=?",
                   (role, int(active), password_hash or row["password_hash"], now(), uid))
        db.execute("UPDATE auth_sessions SET revoked=1 WHERE user_id=?", (uid,))
        for key in changes:
            event(db, actor, {"role": "USER_ROLE_CHANGE", "active": "USER_ENABLE" if active else "USER_DISABLE", "password": "USER_PASSWORD_RESET"}[key], uid)
        return public(db.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone())
