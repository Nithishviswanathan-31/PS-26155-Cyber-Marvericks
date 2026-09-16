import base64
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import time

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.main import app
from app.domain.auth import Role, UserCreateRequest
from app.services import auth_service as auth
from app.storage import auth as store
from app.storage.database import reset_demo_database, get_connection

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "test-only-" + secrets.token_urlsafe(16)


@pytest.fixture
def secured(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATABASE_PATH", tmp_path / "auth.db")
    monkeypatch.setattr(auth, "AUTH_REQUIRED", True)
    monkeypatch.setattr(auth, "AUTH_SECRET", secrets.token_urlsafe(48))
    store.initialize()
    users = {role.value: store.create(UserCreateRequest(username=role.value.lower(), display_name=role.value,
             password=PASSWORD, role=role), {"user_id": "test-seed", "role": "ADMIN"}) for role in Role}
    reset_demo_database()
    with TestClient(app) as client:
        tokens = {}
        for role in Role:
            response = client.post("/api/auth/login", json={"username": role.value.lower(), "password": PASSWORD})
            assert response.status_code == 200
            tokens[role.value] = {"Authorization": "Bearer " + response.json()["access_token"]}
        yield client, users, tokens
    reset_demo_database()


def test_login_current_user_logout_and_invalid_credentials(secured):
    client, users, tokens = secured
    me = client.get("/api/auth/me", headers=tokens["REVIEWER"])
    assert me.status_code == 200 and me.json()["user_id"] == users["REVIEWER"]["user_id"]
    assert "password" not in me.text and me.headers["cache-control"] == "no-store"
    for username, password in [("reviewer", "incorrect"), ("missing", PASSWORD)]:
        bad = client.post("/api/auth/login", json={"username": username, "password": password})
        assert bad.status_code == 401 and bad.json()["error_code"] == "INVALID_CREDENTIALS"
        assert password not in bad.text
    assert client.post("/api/auth/logout", headers=tokens["REVIEWER"]).status_code == 200
    assert client.get("/api/auth/me", headers=tokens["REVIEWER"]).status_code == 401
    assert client.get("/health").status_code == 200


def test_password_hash_and_validation_secrets(secured):
    client, _, tokens = secured
    one, two = auth.hash_password(PASSWORD), auth.hash_password(PASSWORD)
    assert one != two and PASSWORD not in one
    assert auth.verify(PASSWORD, one) and not auth.verify("wrong", one)
    response = client.post("/api/users", headers=tokens["ADMIN"], json={"username": "bad space", "password": PASSWORD, "display_name": "x", "role": "ROOT"})
    assert response.status_code == 422 and PASSWORD not in response.text
    with store.connection() as db:
        assert all(PASSWORD not in row[0] for row in db.execute("SELECT password_hash FROM users"))


def test_invalid_tampered_expired_and_unregistered_tokens(secured):
    client, users, tokens = secured
    raw = tokens["ADMIN"]["Authorization"][7:]
    for value in ["", "not.a.token", "abc", "...", raw + "x", "Basic password", "Bearer ☃".encode().hex()]:
        assert client.get("/api/analyses", headers={"Authorization": "Bearer " + value}).status_code == 401
    body = base64.urlsafe_b64encode(json.dumps({"id": users["ADMIN"]["user_id"], "exp": time.time() - 1}).encode()).decode()
    signed = body + "." + hmac.new(auth.AUTH_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    assert client.get("/api/analyses", headers={"Authorization": "Bearer " + signed}).status_code == 401
    with store.connection() as db:
        db.execute("UPDATE auth_sessions SET expires_at=0 WHERE user_id=?", (users["ADMIN"]["user_id"],))
    assert client.get("/api/analyses", headers=tokens["ADMIN"]).status_code == 401


def test_every_audit_route_has_dependency_and_rejects_anonymous(secured):
    client, _, tokens = secured
    public = {"/api/auth/login"}
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api"):
            continue
        path = route.path
        for name in route.param_convertors:
            path = path.replace("{" + name + "}", "missing")
        if route.path in public:
            continue
        for method in route.methods:
            assert client.request(method, path).status_code == 401, (method, path)
        if not route.path.startswith(("/api/auth", "/api/users")):
            assert any(d.call is auth.authorize_route for d in route.dependant.dependencies)
            if route.methods - {"GET", "HEAD", "OPTIONS"}:
                assert route.name in auth.MUTATION_ROLES
                for role in Role:
                    response = client.post(path, headers=tokens[role.value], json={})
                    if role.value not in auth.MUTATION_ROLES[route.name]:
                        assert response.status_code == 403, (role, path, response.text)
                    else:
                        assert response.status_code not in {401, 403}, (role, path, response.text)


def test_admin_management_and_final_admin(secured):
    client, users, tokens = secured
    for role in ["AUDITOR", "REVIEWER"]:
        assert client.get("/api/users", headers=tokens[role]).status_code == 403
        assert client.post("/api/users", headers=tokens[role], json={}).status_code == 403
        assert client.patch("/api/users/missing", headers=tokens[role], json={}).status_code == 403
    admin = tokens["ADMIN"]
    for change in [{"active": False}, {"role": "AUDITOR"}]:
        assert client.patch(f"/api/users/{users['ADMIN']['user_id']}", headers=admin, json=change).status_code == 409
    payload = {"username": "extra", "display_name": "Extra", "password": PASSWORD, "role": "AUDITOR"}
    created = client.post("/api/users", headers=admin, json=payload)
    assert created.status_code == 201 and "password" not in created.text
    assert client.post("/api/users", headers=admin, json={**payload, "username": "EXTRA"}).status_code == 409
    assert client.post("/api/users", headers=admin, json={**payload, "role": "ROOT"}).status_code == 422
    listing = client.get("/api/users", headers=admin)
    assert len(listing.json()) == 4 and "password_hash" not in listing.text
    assert client.patch("/api/users/missing", headers=admin, json={"active": False}).status_code == 404
    assert client.patch(f"/api/users/{created.json()['user_id']}", headers=admin, json={"active": None}).status_code == 422


def test_disable_role_and_password_changes_revoke_sessions(secured):
    client, users, tokens = secured
    path = "/api/users/" + users["AUDITOR"]["user_id"]
    assert client.patch(path, headers=tokens["ADMIN"], json={"active": False}).status_code == 200
    assert client.get("/api/analyses", headers=tokens["AUDITOR"]).status_code == 401
    assert client.post("/api/auth/login", json={"username": "auditor", "password": PASSWORD}).status_code == 401
    assert client.patch(path, headers=tokens["ADMIN"], json={"active": True, "role": "REVIEWER", "password": PASSWORD + "new"}).status_code == 200
    assert client.post("/api/auth/login", json={"username": "auditor", "password": PASSWORD}).status_code == 401
    login = client.post("/api/auth/login", json={"username": "auditor", "password": PASSWORD + "new"})
    headers = {"Authorization": "Bearer " + login.json()["access_token"]}
    assert client.get("/api/auth/me", headers=headers).json()["role"] == "REVIEWER"
    assert client.post("/api/analyze", headers=headers).status_code == 403


def test_server_actor_and_full_authenticated_workflow(secured):
    client, users, tokens = secured
    original = client.post("/api/analyze", headers=tokens["AUDITOR"], files={"file": ("source.conf", (ROOT / "configs/astranet/unknown-pattern.conf").read_bytes())}).json()
    aid, pid = original["analysis_id"], original["unknown_patterns"][0]["pattern_id"]
    generated = client.post(f"/api/interpretations/{aid}", headers=tokens["REVIEWER"])
    assert generated.status_code == 200
    proposal = client.post(f"/api/mappings/{pid}/suggest", headers=tokens["REVIEWER"]).json()
    for action in ["approve", "correct", "reject", "approve"]:
        payload = {"reviewer_id": users["ADMIN"]["user_id"], "proposal_id": proposal["proposal_id"]}
        if action != "reject":
            payload["semantic_mapping"] = {"management.ssh_enabled": True, "management.telnet_enabled": False}
        response = client.post(f"/api/mappings/{pid}/{action}", headers=tokens["REVIEWER"], json=payload)
        assert response.status_code == 200, response.text
        mapping = response.json()["mapping"]
        assert mapping["reviewer_id"] == users["REVIEWER"]["user_id"]
    events = client.get(f"/api/interpretations/proposals/{proposal['proposal_id']}/history", headers=tokens["AUDITOR"]).json()["events"]
    assert events[-1]["reviewer_id"] == users["REVIEWER"]["user_id"]
    child = client.post(f"/api/analyze/{aid}/reanalyze", headers=tokens["REVIEWER"])
    assert child.status_code == 200 and child.json()["parent_analysis_id"] == aid
    assert client.get(f"/api/reports/{child.json()['analysis_id']}/pdf", headers=tokens["AUDITOR"]).status_code == 200
    deactivated = client.post(f"/api/knowledge/{mapping['mapping_id']}/deactivate", headers=tokens["REVIEWER"], json={"reviewer_id": "impersonated-admin"})
    assert deactivated.status_code == 200
    db = get_connection()
    try:
        reviewer = db.execute("SELECT reviewer_id FROM mapping_approvals WHERE action='DEACTIVATE'").fetchone()[0]
        assert reviewer == users["REVIEWER"]["user_id"]
    finally:
        db.close()
    assert client.get(f"/api/analyze/{aid}", headers=tokens["REVIEWER"]).json() == original
    for path in ["/api/analyses", "/api/findings", "/api/devices", "/api/configurations", "/api/dashboard/summary", "/api/knowledge", "/api/knowledge/review-queue", "/api/batches"]:
        for role in Role:
            assert client.get(path, headers=tokens[role.value]).status_code == 200
    content = (ROOT / "configs/cisco/noncompliant.conf").read_bytes()
    batch = client.post("/api/batches/analyze", headers=tokens["AUDITOR"], files=[("files", ("cisco.conf", content))])
    assert batch.status_code == 200
    items = client.get(f"/api/batches/{batch.json()['batch_id']}/items", headers=tokens["REVIEWER"]).json()
    analysis_id = items[0]["analysis_id"]
    remediation = client.get(f"/api/remediation/{analysis_id}", headers=tokens["AUDITOR"]).json()["remediations"][0]
    assert client.post(f"/api/remediation/{analysis_id}/simulate", headers=tokens["AUDITOR"], json={"remediation_id": remediation["remediation_id"]}).status_code == 200
    assert client.get(f"/api/reports/{analysis_id}/pdf", headers=tokens["AUDITOR"]).status_code == 200
    with store.connection() as db:
        events = [dict(row) for row in db.execute("SELECT * FROM auth_events")]
    assert any(e["action"] == "approve_mapping:COMPLETED" and e["user_id"] == users["REVIEWER"]["user_id"] and e["role"] == "REVIEWER" for e in events)
    assert any(e["action"] == "analyze_batch:COMPLETED" for e in events)
    assert any(e["action"] == "simulate_remediation:COMPLETED" for e in events)
    assert not any(e["user_id"] == "impersonated-admin" for e in events)


def test_demo_reset_preserves_users_and_sessions(secured):
    client, _, tokens = secured
    assert client.post("/api/demo/reset", headers=tokens["ADMIN"]).status_code == 200
    assert len(client.get("/api/users", headers=tokens["ADMIN"]).json()) == 3
    assert client.get("/api/auth/me", headers=tokens["AUDITOR"]).status_code == 200


def test_offline_compatibility_and_management_still_requires_login(secured, monkeypatch):
    client, _, _ = secured
    monkeypatch.setattr(auth, "AUTH_REQUIRED", False)
    assert client.get("/api/auth/me").json()["offline"] is True
    assert client.get("/api/analyses").status_code == 200
    assert client.get("/api/users").status_code == 401
    assert client.get("/api/analyses", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_seed_is_explicit_environment_only_and_nonproduction(secured, monkeypatch):
    from app.seed_users import seed
    client, _, tokens = secured
    monkeypatch.setenv("DEMO_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("DEMO_ADMIN_USERNAME", "seed-admin")
    seed()
    seed()
    assert len(client.get("/api/users", headers=tokens["ADMIN"]).json()) == 4
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError):
        seed()


def test_production_and_secret_configuration_fail_closed(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_REQUIRED", False)
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError): auth.validate_settings()
    monkeypatch.setattr(auth, "AUTH_REQUIRED", True)
    monkeypatch.setattr(auth, "AUTH_SECRET", "")
    with pytest.raises(RuntimeError): auth.validate_settings()


def test_login_throttling(secured):
    client, _, _ = secured
    for _ in range(10):
        assert client.post("/api/auth/login", json={"username": "nonexistent", "password": "bad"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "nonexistent", "password": "bad"}).status_code == 429


def test_role_change_immediately_revokes_existing_session(secured):
    client, users, tokens = secured
    response = client.patch("/api/users/" + users["REVIEWER"]["user_id"], headers=tokens["ADMIN"], json={"role": "AUDITOR"})
    assert response.status_code == 200
    assert client.post("/api/mappings/missing/approve", headers=tokens["REVIEWER"], json={}).status_code == 401
    login = client.post("/api/auth/login", json={"username": "reviewer", "password": PASSWORD})
    fresh = {"Authorization": "Bearer " + login.json()["access_token"]}
    assert client.post("/api/mappings/missing/approve", headers=fresh, json={}).status_code == 403
    with store.connection() as db:
        event = db.execute("SELECT * FROM auth_events WHERE action='USER_ROLE_CHANGE'").fetchone()
        assert event["user_id"] == users["ADMIN"]["user_id"] and event["role"] == "ADMIN"


def test_password_reset_immediately_revokes_existing_session(secured):
    client, users, tokens = secured
    assert client.patch("/api/users/" + users["REVIEWER"]["user_id"], headers=tokens["ADMIN"], json={"password": PASSWORD + "changed"}).status_code == 200
    assert client.get("/api/auth/me", headers=tokens["REVIEWER"]).status_code == 401
    assert client.post("/api/auth/login", json={"username": "reviewer", "password": PASSWORD}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "reviewer", "password": PASSWORD + "changed"}).status_code == 200


def test_final_admin_can_transfer_only_when_another_enabled_admin_exists(secured):
    client, users, tokens = secured
    created = client.post("/api/users", headers=tokens["ADMIN"], json={"username": "second-admin", "display_name": "Second", "role": "ADMIN", "password": PASSWORD}).json()
    assert client.patch("/api/users/" + users["ADMIN"]["user_id"], headers=tokens["ADMIN"], json={"role": "AUDITOR"}).status_code == 200
    assert client.get("/api/users", headers=tokens["ADMIN"]).status_code == 401
    login = client.post("/api/auth/login", json={"username": "second-admin", "password": PASSWORD}).json()
    assert client.patch("/api/users/" + created["user_id"], headers={"Authorization": "Bearer " + login["access_token"]}, json={"active": False}).status_code == 409
