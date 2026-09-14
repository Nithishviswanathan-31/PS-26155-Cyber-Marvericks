"""Reset and seed a reproducible PS 26155 demonstration state.

This script uses only the checked-in synthetic fixtures and the public demo API
routes. It never contacts a device and never executes configuration commands.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.config import is_demo_reset_enabled
from backend.app.main import app
from backend.app.storage.database import reset_demo_database


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _upload(client: TestClient, relative_path: str) -> dict:
    path = PROJECT_ROOT / relative_path
    response = client.post(
        "/api/analyze",
        files={"file": (path.name, path.read_bytes(), "text/plain")},
    )
    response.raise_for_status()
    return response.json()


def main() -> None:
    if not is_demo_reset_enabled():
        raise SystemExit("Demo seeding is disabled when APP_ENV=production or DEMO_RESET_ENABLED=false.")
    reset_demo_database()
    with TestClient(app) as client:
        cisco = _upload(client, "configs/cisco/noncompliant.conf")
        recommendations = client.get(f"/api/remediation/{cisco['analysis_id']}")
        recommendations.raise_for_status()
        remediation = next(
            item for item in recommendations.json()["remediations"] if item["control_id"] == "CTRL-001"
        )
        simulation = client.post(
            f"/api/remediation/{cisco['analysis_id']}/simulate",
            json={"remediation_id": remediation["remediation_id"]},
        )
        simulation.raise_for_status()

        astranet = _upload(client, "configs/astranet/unknown-pattern.conf")
        pattern_id = astranet["unknown_patterns"][0]["pattern_id"]
        suggestion = client.post(f"/api/mappings/{pattern_id}/suggest")
        suggestion.raise_for_status()
        approval = client.post(
            f"/api/mappings/{pattern_id}/approve",
            json={
                "reviewer_id": "demo-seed-reviewer",
                "semantic_mapping": suggestion.json()["semantic_mapping"],
            },
        )
        approval.raise_for_status()
        reanalysis = client.post(f"/api/analyze/{astranet['analysis_id']}/reanalyze")
        reanalysis.raise_for_status()

    print(json.dumps({
        "status": "seeded",
        "demo_only": True,
        "cisco": {
            "analysis_id": cisco["analysis_id"],
            "simulation_id": simulation.json()["simulation_id"],
            "expected_flow": "CTRL-001 FAIL -> simulation -> PASS",
        },
        "astranet": {
            "analysis_id": astranet["analysis_id"],
            "mapping_id": approval.json()["mapping"]["mapping_id"],
            "mapping_version": approval.json()["mapping"]["version"],
            "reanalysis_id": reanalysis.json()["analysis_id"],
            "expected_flow": "UNKNOWN -> approved mapping -> recognized",
        },
    }, indent=2))


if __name__ == "__main__":
    main()
