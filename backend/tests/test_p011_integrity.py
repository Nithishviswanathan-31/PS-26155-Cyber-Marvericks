from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.evidence import build_evidence
from app.domain.mapping import MappingStatus
from app.main import app
from app.parsers.astranet import AstraNetParser
from app.parsers.cisco import CiscoParser
from app.parsers.fortigate import FortiGateParser
from app.parsers.paloalto import PaloAltoParser
from app.storage.database import get_analysis_bundle, get_connection, get_mapping_versions, initialize_database


ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / "configs"


@pytest.fixture(autouse=True)
def isolate_p011_records() -> None:
    initialize_database()
    connection = get_connection()
    try:
        for table in ("mapping_approvals", "mapping_versions", "mappings", "analysis_results"):
            connection.execute(f"DELETE FROM {table}")
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def upload_astranet(client: TestClient) -> tuple[str, dict]:
    response = client.post(
        "/api/analyze",
        files={"file": ("unknown-pattern.conf", (CONFIGS / "astranet" / "unknown-pattern.conf").read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    return payload["analysis_id"], payload


def approve(client: TestClient, pattern_id: str, mapping: dict[str, bool] | None = None) -> dict:
    candidate = client.post(f"/api/mappings/{pattern_id}/suggest").json()
    response = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "integrity-reviewer",
            "semantic_mapping": mapping or candidate["semantic_mapping"],
        },
    )
    assert response.status_code == 200
    return response.json()


def test_reanalysis_creates_independent_children_and_preserves_parent(client: TestClient) -> None:
    analysis_id, original = upload_astranet(client)
    before = get_analysis_bundle(analysis_id)
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    approve(client, pattern_id)

    first = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    second = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()

    assert first["analysis_id"] != second["analysis_id"] != analysis_id
    assert first["parent_analysis_id"] == analysis_id
    assert second["parent_analysis_id"] == analysis_id
    assert first["mapping_version"] == second["mapping_version"] == 1
    assert get_analysis_bundle(analysis_id) == before
    assert get_analysis_bundle(first["analysis_id"])["response"] == first
    assert get_analysis_bundle(second["analysis_id"])["response"] == second


def test_mapping_version_reproducibility_preserves_old_child(client: TestClient) -> None:
    analysis_id, original = upload_astranet(client)
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    approve(client, pattern_id)
    first = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    first_snapshot = get_analysis_bundle(first["analysis_id"])

    approved_v2 = approve(
        client,
        pattern_id,
        {"management.ssh_enabled": False, "management.telnet_enabled": False},
    )
    second = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()

    assert approved_v2["mapping"]["version"] == 2
    assert first["mapping_version"] == 1
    assert second["mapping_version"] == 2
    assert first["results"][0]["result"] == "PASS"
    assert second["results"][0]["result"] == "FAIL"
    assert get_analysis_bundle(first["analysis_id"]) == first_snapshot
    assert [item["status"] for item in get_mapping_versions(pattern_id)] == ["INACTIVE", "APPROVED"]


def test_reanalysis_without_active_mapping_has_structured_error(client: TestClient) -> None:
    analysis_id, _ = upload_astranet(client)
    response = client.post(f"/api/analyze/{analysis_id}/reanalyze")
    assert response.status_code == 409
    assert response.json()["error_code"] == "NO_ACTIVE_MAPPING"
    assert "active approved mapping" in response.json()["detail"]


def test_reanalysis_distinguishes_rejected_mapping(client: TestClient) -> None:
    analysis_id, original = upload_astranet(client)
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    rejected = client.post(
        f"/api/mappings/{pattern_id}/reject",
        json={"reviewer_id": "integrity-reviewer", "reason": "Insufficient evidence."},
    )
    assert rejected.status_code == 200
    response = client.post(f"/api/analyze/{analysis_id}/reanalyze")
    assert response.status_code == 409
    assert response.json()["error_code"] == "REJECTED_MAPPING"


def test_structured_errors_preserve_legacy_detail_text(client: TestClient) -> None:
    missing = client.post("/api/analyze/does-not-exist/reanalyze")
    unsupported = client.post(
        "/api/analyze",
        files={"file": ("unknown.conf", b"not a supported configuration", "text/plain")},
    )
    assert missing.status_code == 404
    assert missing.json() == {
        "detail": "The original analysis was not found.",
        "error_code": "ANALYSIS_NOT_FOUND",
    }
    assert unsupported.status_code == 400
    assert unsupported.json()["error_code"] == "UNSUPPORTED_INPUT"
    assert "Cisco" in unsupported.json()["detail"]


def test_deterministic_evaluation_and_evidence_are_repeatable() -> None:
    parser_inputs = (
        (CiscoParser, "cisco", "compliant.conf"),
        (FortiGateParser, "fortigate", "compliant.conf"),
        (PaloAltoParser, "paloalto", "compliant.conf"),
    )
    controls = load_demo_controls()
    for parser, vendor_dir, filename in parser_inputs:
        text = (CONFIGS / vendor_dir / filename).read_text(encoding="utf-8")
        ir = parser.parse(text, source_file=filename)
        engine = DeterministicControlEngine()
        first = engine.evaluate_all(ir, controls)
        second = engine.evaluate_all(ir, controls)
        first_evidence = [item.model_dump(mode="json") for result in first for item in build_evidence(ir, result)]
        second_evidence = [item.model_dump(mode="json") for result in second for item in build_evidence(ir, result)]
        assert [item.model_dump(mode="json") for item in first] == [item.model_dump(mode="json") for item in second]
        assert first_evidence == second_evidence


def test_cross_vendor_regression_matrix_uses_common_properties() -> None:
    cases = (
        (CiscoParser, "cisco", "cisco_iosxe"),
        (FortiGateParser, "fortigate", "fortigate_fortios"),
        (PaloAltoParser, "paloalto", "paloalto_panos"),
    )
    for parser, directory, vendor in cases:
        text = (CONFIGS / directory / "compliant.conf").read_text(encoding="utf-8")
        assert parser.detect(text)
        ir = parser.parse(text, source_file="compliant.conf")
        assert ir.device.vendor == vendor
        assert "management.ssh_enabled" in ir.normalized_properties
        assert "management.telnet_enabled" in ir.normalized_properties
        evaluations = DeterministicControlEngine().evaluate_all(ir, load_demo_controls())
        assert all(result.result.value == "PASS" for result in evaluations)
        assert all(build_evidence(ir, result) for result in evaluations)

        incomplete = parser.parse(
            (CONFIGS / directory / "unknown.conf").read_text(encoding="utf-8"),
            source_file="unknown.conf",
        )
        incomplete_results = DeterministicControlEngine().evaluate_all(incomplete, load_demo_controls())
        assert {result.result.value for result in incomplete_results} == {"UNKNOWN"}
        assert all(build_evidence(incomplete, result) for result in incomplete_results)

    unknown = AstraNetParser.parse((CONFIGS / "astranet" / "unknown-pattern.conf").read_text(encoding="utf-8"))
    assert unknown.device.vendor == "astranet"
    assert unknown.normalized_properties == {}
    assert {result.result.value for result in DeterministicControlEngine().evaluate_all(unknown, load_demo_controls())} == {"UNKNOWN"}


def test_mapping_status_contract_remains_explicit() -> None:
    assert MappingStatus.APPROVED.value == "APPROVED"
    assert MappingStatus.INACTIVE.value == "INACTIVE"
