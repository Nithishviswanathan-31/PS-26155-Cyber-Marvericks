"""Reset and seed a reproducible PS 26155 demonstration state.

This script uses only the checked-in synthetic fixtures and the public demo API
routes. It never contacts a device and never executes configuration commands.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from backend.app.config import is_demo_reset_enabled
from backend.app.main import app
from backend.app.storage.database import reset_demo_database


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
        # 1. Cisco IOS/IOS-XE Non-compliant + Remediation Simulation
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

        # 2. FortiGate/FortiOS Compliant
        fortigate = _upload(client, "configs/fortigate/compliant.conf")

        # 3. Palo Alto/PAN-OS Mixed
        paloalto = _upload(client, "configs/paloalto/mixed.conf")

        # 4. AstraNet Synthetic Unknown-Pattern + Suggestion + Approval + Reanalysis
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

        # 5. Multi-Vendor Fleet Batch Ingestion (Scenario 5.E Bulk Audit Demo)
        fleet_configs = [
            PROJECT_ROOT / "configs/cisco/noncompliant.conf",
            PROJECT_ROOT / "configs/fortigate/compliant.conf",
            PROJECT_ROOT / "configs/paloalto/mixed.conf",
            PROJECT_ROOT / "configs/astranet/unknown-pattern.conf",
        ]
        fleet_files = [
            ("files", (path.name, path.read_bytes(), "text/plain"))
            for path in fleet_configs
        ]
        batch_response = client.post("/api/batches/analyze", files=fleet_files)
        batch_response.raise_for_status()
        batch_data = batch_response.json()

    print(json.dumps({
        "status": "seeded",
        "demo_only": True,
        "cisco": {
            "analysis_id": cisco["analysis_id"],
            "vendor": cisco["vendor"],
            "hostname": cisco.get("device", {}).get("hostname"),
            "simulation_id": simulation.json()["simulation_id"],
            "expected_flow": "CTRL-001 FAIL -> simulation -> PASS",
        },
        "fortigate": {
            "analysis_id": fortigate["analysis_id"],
            "vendor": fortigate["vendor"],
            "hostname": fortigate.get("device", {}).get("hostname"),
            "expected_flow": "Compliant FortiGate parsing & deterministic evaluation",
        },
        "paloalto": {
            "analysis_id": paloalto["analysis_id"],
            "vendor": paloalto["vendor"],
            "hostname": paloalto.get("device", {}).get("hostname"),
            "expected_flow": "PAN-OS mixed compliance evaluation with vendor remediation",
        },
        "astranet": {
            "analysis_id": astranet["analysis_id"],
            "mapping_id": approval.json()["mapping"]["mapping_id"],
            "mapping_version": approval.json()["mapping"]["version"],
            "reanalysis_id": reanalysis.json()["analysis_id"],
            "expected_flow": "UNKNOWN -> approved mapping -> recognized",
        },
        "fleet_batch": {
            "batch_id": batch_data["batch_id"],
            "status": batch_data["status"],
            "total_items": batch_data["total_items"],
            "successful_items": batch_data["successful_items"],
            "vendors_detected": batch_data.get("summary", {}).get("vendors_detected"),
            "devices_analyzed": batch_data.get("summary", {}).get("devices_analyzed"),
            "findings_aggregate": {
                "pass": batch_data.get("summary", {}).get("pass_count"),
                "fail": batch_data.get("summary", {}).get("fail_count"),
                "unknown": batch_data.get("summary", {}).get("unknown_count"),
            },
            "expected_flow": "Unified multi-vendor fleet bulk ingestion with per-device reporting",
        },
    }, indent=2))


if __name__ == "__main__":
    main()
