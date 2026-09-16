import time
from fastapi import APIRouter, Depends, Request, Response
from ..domain.auth import LoginRequest, UserCreateRequest, UserUpdateRequest
from ..services import auth_service as service
from ..storage import auth as store

router = APIRouter(prefix="/api/auth", tags=["authentication"])
users_router = APIRouter(prefix="/api/users", tags=["user administration"], dependencies=[Depends(service.administrator)])
# A dummy hash prevents the username-not-found path skipping password hashing.
_DUMMY_HASH = service.hash_password("unused-dummy-password-for-timing")


@router.post("/login")
def login(request: LoginRequest, response: Response):
    key = service.fingerprint(request.username)
    stamp = time.time()
    with store.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        limit = db.execute("SELECT * FROM login_limits WHERE login_key=?", (key,)).fetchone()
        if limit and stamp - limit["window_start"] < 300 and limit["attempts"] >= 10:
            raise service.AuthError(429, "LOGIN_LIMIT", "Try signing in again later.")
        if not limit or stamp - limit["window_start"] >= 300:
            db.execute("INSERT INTO login_limits VALUES (?,1,?) ON CONFLICT(login_key) DO UPDATE SET attempts=1,window_start=excluded.window_start", (key, stamp))
        else:
            db.execute("UPDATE login_limits SET attempts=attempts+1 WHERE login_key=?", (key,))
        row = db.execute("SELECT * FROM users WHERE username=?", (request.username,)).fetchone()
    valid = service.verify(request.password, row["password_hash"] if row else _DUMMY_HASH)
    if not row or not valid or not row["active"]:
        raise service.AuthError(401, "INVALID_CREDENTIALS", "Invalid credentials.")
    value = service.token(dict(row))
    with store.connection() as db:
        db.execute("DELETE FROM login_limits WHERE login_key=?", (key,))
    response.headers["Cache-Control"] = "no-store"
    return {"access_token": value, "token_type": "bearer", "expires_in": service.AUTH_TTL_SECONDS, "user": store.public(row)}


@router.get("/me")
def me(response: Response, user=Depends(service.actor)):
    response.headers["Cache-Control"] = "no-store"
    return user


@router.post("/logout")
def logout(request: Request, user=Depends(service.actor)):
    if not user.get("offline"):
        with store.connection() as db:
            db.execute("UPDATE auth_sessions SET revoked=1 WHERE token_hash=?", (service.fingerprint(request.headers["authorization"][7:]),))
            store.event(db, user, "LOGOUT", user["user_id"])
    return {"status": "logged_out"}


@users_router.get("")
def list_users():
    with store.connection() as db:
        return [store.public(row) for row in db.execute("SELECT * FROM users ORDER BY username")]


@users_router.post("", status_code=201)
def create_user(request: UserCreateRequest, user=Depends(service.administrator)):
    return store.create(request, user)


@users_router.patch("/{user_id}")
def update_user(user_id: str, request: UserUpdateRequest, user=Depends(service.administrator)):
    return store.update(user_id, request, user)
