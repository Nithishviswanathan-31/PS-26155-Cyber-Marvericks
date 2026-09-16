"""Run explicitly: python -m app.seed_users. Never invoked by startup or demo reset."""
import os
from .domain.auth import Role, UserCreateRequest
from .storage import auth as store


def seed():
    if os.getenv("APP_ENV", "development").lower() in {"production", "prod"}:
        raise RuntimeError("Demo user seeding is disabled in production")
    requests = []
    for role in Role:
        password = os.getenv(f"DEMO_{role.value}_PASSWORD")
        if password:
            try:
                requests.append(UserCreateRequest(username=os.getenv(f"DEMO_{role.value}_USERNAME", role.value.lower()),
                                                  display_name=f"Local {role.value.title()}", role=role, password=password))
            except ValueError:
                raise RuntimeError("Invalid seed configuration: use valid usernames and passwords of 12..256 characters") from None
    if not requests:
        raise RuntimeError("Set DEMO_ADMIN_PASSWORD and optionally DEMO_AUDITOR_PASSWORD / DEMO_REVIEWER_PASSWORD")
    store.initialize()
    for request in requests:
        with store.connection() as db:
            exists = db.execute("SELECT 1 FROM users WHERE username=?", (request.username,)).fetchone()
        if not exists:
            store.create(request, {"user_id": "local-seed", "role": "ADMIN"})


if __name__ == "__main__":
    seed()
