"""Compatibility guard for V1 semantics after intentional V2 response growth."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


ROOT = Path(__file__).resolve().parents[2]


def test_v1_root_controls_statuses_and_evidence_remain_semantically_stable():
    """V2 may add diagnostic rows; the original four control meanings persist."""
    expected = {
        "compliant.conf": "PASS",
        "noncompliant.conf": "FAIL",
        "unknown.conf": "UNKNOWN",
    }
    with TestClient(app) as client:
        for filename, status in expected.items():
            response = client.post(
                "/api/analyze",
                files={"file": (filename, (ROOT / "configs" / "cisco" / filename).read_bytes(), "text/plain")},
            )
            assert response.status_code == 200
            payload = response.json()
            roots = [item for item in payload["results"] if item["control_id"] in {"CTRL-001", "CTRL-002", "CTRL-003", "CTRL-004"}]
            assert [item["control_id"] for item in roots] == ["CTRL-001", "CTRL-002", "CTRL-003", "CTRL-004"]
            assert {item["result"] for item in roots} == {status}
            evidence = [item for item in payload["evidence"] if item["control_id"] in {"CTRL-001", "CTRL-002", "CTRL-003", "CTRL-004"}]
            assert {item["control_id"] for item in evidence} == {"CTRL-001", "CTRL-002", "CTRL-003", "CTRL-004"}
