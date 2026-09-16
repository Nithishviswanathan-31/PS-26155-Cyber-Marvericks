from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.storage.database import reset_demo_database

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client():
    reset_demo_database()
    with TestClient(app) as value:
        yield value
    reset_demo_database()


def parts(*entries):
    return [("files", (name, content, "text/plain")) for name, content in entries]


def test_batch_processes_multiple_valid_files_and_exposes_items(client):
    compliant = (ROOT / "configs/cisco/compliant.conf").read_bytes()
    noncompliant = (ROOT / "configs/cisco/noncompliant.conf").read_bytes()
    response = client.post("/api/batches/analyze", files=parts(("one.conf", compliant), ("two.conf", noncompliant)))
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "COMPLETED"
    assert payload["summary"] == {"total": 2, "processed": 2, "successful": 2, "failed": 0, "duplicates": 0, "pass_analyses": 1, "fail_analyses": 1, "unknown_analyses": 0}
    items = client.get(f"/api/batches/{payload['batch_id']}/items").json()
    assert {item["processing_status"] for item in items} == {"COMPLETED"}
    assert {item["compliance_status"] for item in items} == {"PASS", "FAIL"}
    assert all(item["analysis_id"] and item["configuration_id"] for item in items)


def test_mixed_batch_isolates_invalid_item_and_preserves_valid_analysis(client):
    valid = (ROOT / "configs/cisco/compliant.conf").read_bytes()
    response = client.post("/api/batches/analyze", files=parts(("valid.conf", valid), ("bad.xml", b"not config")))
    payload = response.json()
    assert response.status_code == 200 and payload["status"] == "COMPLETED_WITH_ERRORS"
    assert payload["successful_items"] == 1 and payload["failed_items"] == 1
    items = client.get(f"/api/batches/{payload['batch_id']}/items").json()
    good = next(item for item in items if item["source_filename"] == "valid.conf")
    bad = next(item for item in items if item["source_filename"] == "bad.xml")
    assert good["analysis_id"] and bad["analysis_id"] is None
    assert bad["error_code"] == "UNSUPPORTED_INPUT"


def test_duplicate_content_is_visible_and_history_is_preserved(client):
    content = (ROOT / "configs/cisco/compliant.conf").read_bytes()
    payload = client.post("/api/batches/analyze", files=parts(("first.conf", content), ("second.conf", content))).json()
    assert payload["duplicate_items"] == 1
    items = client.get(f"/api/batches/{payload['batch_id']}/items").json()
    duplicate = next(item for item in items if item["source_filename"] == "second.conf")
    assert duplicate["processing_status"] == "DUPLICATE"
    assert duplicate["duplicate_of_configuration_id"]
    assert duplicate["analysis_id"]


def test_empty_and_unsupported_items_are_isolated(client):
    valid = (ROOT / "configs/cisco/compliant.conf").read_bytes()
    payload = client.post("/api/batches/analyze", files=parts(("empty.conf", b""), ("archive.zip", b"PK"), ("valid.conf", valid))).json()
    assert payload["successful_items"] == 1 and payload["failed_items"] == 2
    items = client.get(f"/api/batches/{payload['batch_id']}/items").json()
    errors = {item["source_filename"]: item["error_code"] for item in items if item["processing_status"] == "FAILED"}
    assert errors == {"empty.conf": "MALFORMED_CONFIGURATION", "archive.zip": "UNSUPPORTED_INPUT"}


def test_file_count_limit_is_rejected_before_processing(client):
    response = client.post("/api/batches/analyze", files=parts(*[(f"{i}.conf", b"x") for i in range(26)]))
    assert response.status_code == 413
    assert response.json()["error_code"] == "BATCH_LIMIT_EXCEEDED"


def test_single_file_analysis_remains_available_after_batch_support(client):
    content = (ROOT / "configs/cisco/compliant.conf").read_bytes()
    response = client.post("/api/analyze", files={"file": ("single.conf", content, "text/plain")})
    assert response.status_code == 200
    assert response.json()["results"][0]["result"] == "PASS"


def test_oversized_item_is_failed_without_invalidating_other_items(client):
    valid = (ROOT / "configs/cisco/compliant.conf").read_bytes()
    oversized = b"x" * (1024 * 1024 + 1)
    payload = client.post("/api/batches/analyze", files=parts(("large.conf", oversized), ("valid.conf", valid))).json()
    assert payload["successful_items"] == 1 and payload["failed_items"] == 1
    items = client.get(f"/api/batches/{payload['batch_id']}/items").json()
    large = next(item for item in items if item["source_filename"] == "large.conf")
    assert large["error_code"] == "MALFORMED_CONFIGURATION" and large["analysis_id"] is None


def test_batch_total_size_limit_is_reported_per_item(client, monkeypatch):
    monkeypatch.setattr("app.api.batches.BATCH_MAX_TOTAL_BYTES", 10)
    payload = client.post("/api/batches/analyze", files=parts(("one.conf", b"123456"), ("two.conf", b"789012"))).json()
    assert payload["failed_items"] >= 1
    items = client.get(f"/api/batches/{payload['batch_id']}/items").json()
    assert any(item["error_code"] == "BATCH_LIMIT_EXCEEDED" for item in items)
