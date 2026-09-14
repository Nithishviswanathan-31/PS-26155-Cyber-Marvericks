from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app.main import app
from app.storage.database import get_analysis_bundle, get_connection, initialize_database, reset_demo_database


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def clean_demo_records() -> None:
    initialize_database()
    reset_demo_database()


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def upload(client: TestClient, relative_path: str) -> dict:
    path = ROOT / relative_path
    response = client.post(
        "/api/analyze",
        files={"file": (path.name, path.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    return response.json()


def pdf_text(content: bytes) -> str:
    reader = PdfReader(BytesIO(content))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_cisco_compliance_simulation_and_pdf_demo_path(client: TestClient) -> None:
    original = upload(client, "configs/cisco/noncompliant.conf")
    original_bundle = get_analysis_bundle(original["analysis_id"])
    ctrl1 = next(item for item in original["results"] if item["control_id"] == "CTRL-001")
    assert ctrl1["result"] == "FAIL"
    assert any(item["control_id"] == "CTRL-001" for item in original["evidence"])

    recommendations = client.get(f"/api/remediation/{original['analysis_id']}")
    assert recommendations.status_code == 200
    remediation = next(item for item in recommendations.json()["remediations"] if item["control_id"] == "CTRL-001")
    assert remediation["simulation_only"] is True

    simulation = client.post(
        f"/api/remediation/{original['analysis_id']}/simulate",
        json={"remediation_id": remediation["remediation_id"]},
    )
    assert simulation.status_code == 200
    simulation_payload = simulation.json()
    assert simulation_payload["before_result"] == "FAIL"
    assert simulation_payload["after_result"] == "PASS"
    assert simulation_payload["simulation_only"] is True
    assert any(item["evidence_source"] == "SIMULATED_REMEDIATION" for item in simulation_payload["evidence"])
    assert get_analysis_bundle(original["analysis_id"]) == original_bundle

    report = client.get(f"/api/reports/{original['analysis_id']}/pdf")
    assert report.status_code == 200
    text = pdf_text(report.content)
    assert "CTRL-001" in text
    assert "Before Result" in text
    assert "After Result" in text
    assert "SIMULATION ONLY" in text
    assert "No production device was contacted or modified" in text


def test_astranet_adaptive_learning_and_pdf_demo_path(client: TestClient) -> None:
    original = upload(client, "configs/astranet/unknown-pattern.conf")
    assert original["vendor"] == "astranet"
    assert {item["result"] for item in original["results"]} == {"UNKNOWN"}
    assert original["unknown_patterns"][0]["raw_pattern"] == "guard-channel lattice-secure"
    original_bundle = get_analysis_bundle(original["analysis_id"])

    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    suggestion = client.post(f"/api/mappings/{pattern_id}/suggest")
    assert suggestion.status_code == 200
    candidate = suggestion.json()
    assert candidate["status"] == "SUGGESTED"
    assert candidate["requires_human_approval"] is True

    approval = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "p014-demo-reviewer", "semantic_mapping": candidate["semantic_mapping"]},
    )
    assert approval.status_code == 200
    assert approval.json()["mapping"]["version"] == 1
    assert approval.json()["mapping"]["active"] is True

    child = client.post(f"/api/analyze/{original['analysis_id']}/reanalyze")
    assert child.status_code == 200
    child_payload = child.json()
    assert child_payload["parent_analysis_id"] == original["analysis_id"]
    assert child_payload["mapping_version"] == 1
    assert child_payload["recognized_patterns"][0]["state"] == "RECOGNIZED_VIA_APPROVED_MAPPING"
    assert get_analysis_bundle(original["analysis_id"]) == original_bundle

    report = client.get(f"/api/reports/{child_payload['analysis_id']}/pdf")
    assert report.status_code == 200
    text = pdf_text(report.content)
    assert "Adaptive Mapping" in text
    assert "Mapping Version" in text
    assert "RECOGNIZED_VIA_APPROVED_MAPPING" in text
    assert "Parent Analysis" in text
    assert "Evidence Details" in text


def test_demo_reset_preserves_schema_and_is_blocked_in_production(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    analysis = upload(client, "configs/cisco/compliant.conf")
    assert get_analysis_bundle(analysis["analysis_id"]) is not None

    reset = client.post("/api/demo/reset")
    assert reset.status_code == 200
    assert reset.json()["demo_only"] is True
    assert get_analysis_bundle(analysis["analysis_id"]) is None

    connection = get_connection()
    try:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()

    monkeypatch.setenv("APP_ENV", "production")
    blocked = client.post("/api/demo/reset")
    assert blocked.status_code == 403
    assert blocked.json()["error_code"] == "DEMO_RESET_DISABLED"


def test_demo_input_errors_are_structured_and_do_not_expose_tracebacks(client: TestClient) -> None:
    unsupported = client.post("/api/analyze", files={"file": ("sample.bin", b"not a supported config", "application/octet-stream")})
    assert unsupported.status_code == 400
    assert unsupported.json()["error_code"] == "UNSUPPORTED_INPUT"
    assert "Traceback" not in unsupported.text

    missing_report = client.get("/api/reports/missing-demo-analysis/pdf")
    assert missing_report.status_code == 404
    assert missing_report.json()["error_code"] == "ANALYSIS_NOT_FOUND"
    assert "Traceback" not in missing_report.text

