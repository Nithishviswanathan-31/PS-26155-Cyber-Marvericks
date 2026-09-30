from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.domain.remediation import RemediationDefinition, SimulationRequest
from app.main import app
from app.storage.database import get_analysis_bundle, get_connection, get_simulation_result, initialize_database


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def isolate_simulation_records() -> None:
    initialize_database()
    connection = get_connection()
    try:
        connection.execute("DELETE FROM simulation_results")
        connection.execute("DELETE FROM interpretation_events")
        connection.execute("DELETE FROM interpretation_proposals")
        connection.execute("DELETE FROM analysis_results")
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def upload(client: TestClient, vendor: str, filename: str) -> tuple[str, dict]:
    path = ROOT / "configs" / vendor / filename
    response = client.post(
        "/api/analyze",
        files={"file": (filename, path.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    return payload["analysis_id"], payload


def test_remediation_lookup_is_fail_only_and_simulation_only(client: TestClient) -> None:
    fail_id, _ = upload(client, "cisco", "noncompliant.conf")
    pass_id, _ = upload(client, "cisco", "compliant.conf")

    fail_response = client.get(f"/api/remediation/{fail_id}")
    pass_response = client.get(f"/api/remediation/{pass_id}")

    assert fail_response.status_code == 200
    remediations = fail_response.json()["remediations"]
    assert {item["control_id"] for item in remediations} == {"CTRL-001", "CTRL-002", "CTRL-003", "CTRL-004"}
    assert all(item["simulation_only"] is True and item["simulation_capability"] == "DETERMINISTIC" for item in remediations)
    assert pass_response.status_code == 200
    assert pass_response.json()["remediations"] == []


def test_cisco_simulation_reaudits_copy_and_preserves_original(client: TestClient) -> None:
    analysis_id, original = upload(client, "cisco", "noncompliant.conf")
    before = get_analysis_bundle(analysis_id)
    remediation = client.get(f"/api/remediation/{analysis_id}").json()["remediations"][0]

    response = client.post(
        f"/api/remediation/{analysis_id}/simulate",
        json={"remediation_id": remediation["remediation_id"]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["simulation_id"]
    assert payload["parent_analysis_id"] == analysis_id
    assert payload["before_result"] == "FAIL"
    assert payload["after_result"] == "PASS"
    assert payload["simulation_only"] is True
    assert {change["property"] for change in payload["simulated_changes"]} == {
        "management.ssh_enabled",
        "management.telnet_enabled",
    }
    assert {change["before_value"] for change in payload["simulated_changes"]} == {False, True}
    assert {change["after_value"] for change in payload["simulated_changes"]} == {False, True}

    simulated_evidence = [item for item in payload["evidence"] if item["control_id"] == "CTRL-001"]
    assert simulated_evidence
    assert all(item["evidence_source"] == "SIMULATED_REMEDIATION" for item in simulated_evidence)
    assert all(item["source_file"] is None for item in simulated_evidence)
    assert all(item["original_source_file"] == "noncompliant.conf" for item in simulated_evidence)
    assert all(item["original_line_start"] >= 1 for item in simulated_evidence)
    assert all(item["original_raw_excerpt"] for item in simulated_evidence)
    assert all(item["simulation_id"] == payload["simulation_id"] for item in simulated_evidence)

    assert get_analysis_bundle(analysis_id) == before
    assert original["results"][0]["result"] == "FAIL"
    assert get_simulation_result(payload["simulation_id"])["after_result"] == "PASS"


@pytest.mark.parametrize(
    ("vendor", "expected_vendor"),
    [("fortigate", "fortigate_fortios"), ("paloalto", "paloalto_panos")],
)
def test_supported_vendor_simulations_use_generic_reaudit(
    client: TestClient,
    vendor: str,
    expected_vendor: str,
) -> None:
    analysis_id, analysis = upload(client, vendor, "noncompliant.conf")
    assert analysis["vendor"] == expected_vendor
    remediation = client.get(f"/api/remediation/{analysis_id}").json()["remediations"][0]
    response = client.post(
        f"/api/remediation/{analysis_id}/simulate",
        json={"remediation_id": remediation["remediation_id"]},
    )
    assert response.status_code == 200
    assert response.json()["before_result"] == "FAIL"
    assert response.json()["after_result"] == "PASS"


def test_repeated_simulations_are_independent(client: TestClient) -> None:
    analysis_id, _ = upload(client, "cisco", "noncompliant.conf")
    remediation = client.get(f"/api/remediation/{analysis_id}").json()["remediations"][0]
    first = client.post(
        f"/api/remediation/{analysis_id}/simulate",
        json={"remediation_id": remediation["remediation_id"]},
    ).json()
    second = client.post(
        f"/api/remediation/{analysis_id}/simulate",
        json={"remediation_id": remediation["remediation_id"]},
    ).json()
    assert first["simulation_id"] != second["simulation_id"]
    assert first["before_result"] == second["before_result"] == "FAIL"
    assert first["after_result"] == second["after_result"] == "PASS"


def test_simulation_errors_are_structured_and_commands_are_not_requestable(client: TestClient) -> None:
    missing = client.get("/api/remediation/not-found")
    assert missing.status_code == 404
    assert missing.json()["error_code"] == "ANALYSIS_NOT_FOUND"

    analysis_id, _ = upload(client, "cisco", "noncompliant.conf")
    unavailable = client.post(
        f"/api/remediation/{analysis_id}/simulate",
        json={"remediation_id": "REM-NOT-AVAILABLE"},
    )
    assert unavailable.status_code == 404
    assert unavailable.json()["error_code"] == "REMEDIATION_NOT_AVAILABLE"

    with pytest.raises(ValidationError):
        SimulationRequest.model_validate({"remediation_id": "x", "execute": True})

    with pytest.raises(ValidationError):
        RemediationDefinition.model_validate(
            {
                "remediation_id": "unsafe",
                "control_id": "CTRL-001",
                "vendor": "cisco_iosxe",
                "title": "unsafe",
                "description": "unsafe",
                "commands": ["x"],
                "target_properties": ["management.ssh_enabled"],
                "expected_state": {"management.ssh_enabled": True},
                "risk_level": "MEDIUM",
                "simulation_only": False,
            }
        )


def test_capabilities_and_explicit_simulation_reanalysis(client: TestClient) -> None:
    capabilities = client.get("/api/remediation/capabilities?vendor=cisco_iosxe&control_id=CTRL-002")
    assert capabilities.status_code == 200
    assert capabilities.json()[0]["remediation_id"] == "REM-CTRL-002-CISCO"
    analysis_id, _ = upload(client, "cisco", "noncompliant.conf")
    logging_remediation = next(item for item in client.get(f"/api/remediation/{analysis_id}").json()["remediations"] if item["control_id"] == "CTRL-002")
    simulation = client.post(f"/api/remediation/{analysis_id}/simulate", json={"remediation_id": logging_remediation["remediation_id"]}).json()
    assert simulation["compliance_final"] is False
    explicit = client.post(f"/api/remediation/simulations/{simulation['simulation_id']}/reanalyze")
    assert explicit.status_code == 200
    assert explicit.json()["parent_analysis_id"] == analysis_id
    assert next(item for item in explicit.json()["results"] if item["control_id"] == "CTRL-002")["result"] == "PASS"
