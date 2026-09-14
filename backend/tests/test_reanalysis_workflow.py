from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.domain.mapping import MappingStatus, MappingVersion
from app.main import app
from app.parsers.astranet import AstraNetParser
from app.services.mapping_application_service import MappingApplicationError, MappingApplicationService
from app.storage.database import get_analysis_bundle, get_connection, get_mapping_versions, initialize_database


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "configs" / "astranet" / "unknown-pattern.conf"


@pytest.fixture(autouse=True)
def isolate_mapping_records() -> None:
    initialize_database()
    connection = get_connection()
    try:
        connection.execute("DELETE FROM mapping_approvals")
        connection.execute("DELETE FROM mapping_versions")
        connection.execute("DELETE FROM mappings")
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def upload_original(client: TestClient) -> tuple[str, dict]:
    response = client.post(
        "/api/analyze",
        files={"file": (CONFIG_PATH.name, CONFIG_PATH.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    return payload["analysis_id"], payload


def approve_mapping(client: TestClient, pattern_id: str, mapping: dict[str, bool] | None = None) -> dict:
    candidate = client.post(f"/api/mappings/{pattern_id}/suggest")
    assert candidate.status_code == 200
    semantic_mapping = mapping or candidate.json()["semantic_mapping"]
    response = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "demo-reviewer", "semantic_mapping": semantic_mapping},
    )
    assert response.status_code == 200
    return response.json()


def test_approved_mapping_is_applied_to_copy_and_recognized(client: TestClient) -> None:
    analysis_id, original = upload_original(client)
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    approved = approve_mapping(client, pattern_id)
    reanalysis = client.post(f"/api/analyze/{analysis_id}/reanalyze")

    assert reanalysis.status_code == 200
    payload = reanalysis.json()
    assert payload["analysis_id"] != analysis_id
    assert payload["parent_analysis_id"] == analysis_id
    assert payload["reanalyzed"] is True
    assert payload["mapping_id"] == approved["mapping"]["mapping_id"]
    assert payload["mapping_version"] == 1
    assert payload["message"] == "Re-analysis completed using approved mapping v1."
    assert payload["recognized_patterns"][0]["state"] == "RECOGNIZED_VIA_APPROVED_MAPPING"
    assert payload["results"][0]["result"] == "PASS"


def test_original_analysis_and_ir_remain_unchanged(client: TestClient) -> None:
    analysis_id, original = upload_original(client)
    before = get_analysis_bundle(analysis_id)
    assert before is not None
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    approve_mapping(client, pattern_id)
    child = client.post(f"/api/analyze/{analysis_id}/reanalyze")
    assert child.status_code == 200

    assert get_analysis_bundle(analysis_id) == before
    assert before["response"]["reanalyzed"] is False
    assert before["response"]["parent_analysis_id"] is None
    assert before["security_ir"]["normalized_properties"] == {}


def test_reanalysis_requires_active_approved_mapping(client: TestClient) -> None:
    analysis_id, _ = upload_original(client)
    blocked = client.post(f"/api/analyze/{analysis_id}/reanalyze")
    assert blocked.status_code == 409
    assert "active approved mapping" in blocked.json()["detail"]

    analysis_id, original = upload_original(client)
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    rejected = client.post(
        f"/api/mappings/{pattern_id}/reject",
        json={"reviewer_id": "demo-reviewer", "reason": "Rejected for demo."},
    )
    assert rejected.status_code == 200
    assert client.post(f"/api/analyze/{analysis_id}/reanalyze").status_code == 409


def test_reanalysis_evidence_preserves_mapping_provenance(client: TestClient) -> None:
    analysis_id, original = upload_original(client)
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    approved = approve_mapping(client, pattern_id)["mapping"]
    payload = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    evidence = next(item for item in payload["evidence"] if item["property"] == "management.ssh_enabled")

    assert evidence["evidence_source"] == "APPROVED_MAPPING"
    assert evidence["mapping_id"] == approved["mapping_id"]
    assert evidence["mapping_version"] == 1
    assert evidence["source_file"] is None
    assert evidence["line_start"] is None
    assert evidence["original_pattern"] == "guard-channel lattice-secure"
    assert evidence["original_source_file"] == "unknown-pattern.conf"
    assert evidence["original_line_start"] == 5
    assert evidence["original_raw_excerpt"] == "guard-channel lattice-secure"


def test_new_reanalysis_uses_current_mapping_version_and_old_child_stays_unchanged(client: TestClient) -> None:
    analysis_id, original = upload_original(client)
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    approve_mapping(client, pattern_id)
    first = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    corrected = approve_mapping(client, pattern_id, {"management.ssh_enabled": False, "management.telnet_enabled": False})
    second = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()

    assert corrected["mapping"]["version"] == 2
    assert first["mapping_version"] == 1
    assert first["results"][0]["result"] == "PASS"
    assert second["mapping_version"] == 2
    assert second["results"][0]["result"] == "FAIL"
    history = get_mapping_versions(pattern_id)
    assert [item["status"] for item in history] == ["INACTIVE", "APPROVED"]
    assert history[0]["active"] is False
    assert history[1]["active"] is True


def test_mapping_application_rejects_inactive_and_rejected_states() -> None:
    ir = AstraNetParser.parse(CONFIG_PATH.read_text(encoding="utf-8"))
    values = {
        "mapping_id": "mapping-test",
        "pattern_id": "astranet-unknown-5",
        "vendor": "astranet",
        "pattern_signature": "signature",
        "proposed_mapping": {"management.ssh_enabled": True},
        "approved_mapping": {"management.ssh_enabled": True},
        "version": 1,
        "reviewer_id": "reviewer",
        "action": "APPROVE",
        "created_at": "2026-09-02T00:00:00Z",
        "updated_at": "2026-09-02T00:00:00Z",
        "active": False,
    }
    for state in (MappingStatus.INACTIVE, MappingStatus.REJECTED):
        mapping = MappingVersion.model_validate({**values, "status": state})
        with pytest.raises(MappingApplicationError):
            MappingApplicationService().apply(ir, mapping)


def test_mapping_application_does_not_overwrite_existing_property() -> None:
    ir = AstraNetParser.parse(CONFIG_PATH.read_text(encoding="utf-8"))
    ir.normalized_properties["management.ssh_enabled"] = False
    mapping = MappingVersion(
        mapping_id="mapping-test",
        pattern_id="astranet-unknown-5",
        vendor="astranet",
        pattern_signature="signature",
        proposed_mapping={"management.ssh_enabled": True},
        approved_mapping={"management.ssh_enabled": True},
        status=MappingStatus.APPROVED,
        version=1,
        reviewer_id="reviewer",
        action="APPROVE",
        created_at="2026-09-02T00:00:00Z",
        updated_at="2026-09-02T00:00:00Z",
        active=True,
    )
    with pytest.raises(MappingApplicationError):
        MappingApplicationService().apply(ir, mapping)
    assert ir.normalized_properties["management.ssh_enabled"] is False
