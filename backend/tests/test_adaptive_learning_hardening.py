from datetime import datetime, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.domain.control_engine import DeterministicControlEngine
from app.domain.interpretation import AIProposal
from app.domain.mapping import (
    CandidateMappingSuggestion,
    MappingStatus,
    MappingVersion,
)
from app.domain.security_ir import SecurityIR, UnknownPattern
from app.main import app
from app.parsers.astranet import AstraNetParser
from app.services.ai_suggestion_service import LocalDemoSuggestionService
from app.services.interpretation_service import DemoInterpretationProvider
from app.storage.database import (
    deactivate_knowledge,
    find_knowledge,
    get_analysis_bundle,
    get_connection,
    get_interpretation_proposals,
    get_latest_mapping,
    get_mapping_versions,
    initialize_database,
    list_knowledge,
    verify_integrity_chain,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "configs" / "astranet" / "unknown-pattern.conf"


@pytest.fixture(autouse=True)
def isolate_adaptive_learning_records() -> None:
    initialize_database()
    connection = get_connection()
    try:
        connection.execute("DELETE FROM interpretation_events")
        connection.execute("DELETE FROM interpretation_proposals")
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


def _upload_astranet(client: TestClient) -> dict:
    response = client.post(
        "/api/analyze",
        files={"file": (CONFIG_PATH.name, CONFIG_PATH.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    return response.json()


# 1. AstraNet unknown detection
def test_01_astranet_unknown_detection(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    assert analysis["vendor"] == "astranet"
    assert len(analysis["unknown_patterns"]) >= 1

    pattern = analysis["unknown_patterns"][0]
    assert pattern["pattern_id"].startswith("astranet-unknown-")
    assert pattern["raw_pattern"] == "guard-channel lattice-secure"
    assert pattern["source_file"] == "unknown-pattern.conf"
    assert pattern["line_start"] == 5
    assert pattern["status"] == "UNKNOWN"

    # Deterministic control evaluation yields UNKNOWN for controls depending on unmapped property
    ctrl_results = {r["control_id"]: r["result"] for r in analysis["results"]}
    assert ctrl_results["CTRL-001"] == "UNKNOWN"


# 2. Proposal generation
def test_02_proposal_generation(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # Candidate mapping suggestion via /api/mappings/{pattern_id}/suggest
    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    assert suggest_resp.status_code == 200
    suggestion = suggest_resp.json()
    assert suggestion["pattern_id"] == pattern_id
    assert suggestion["status"] == "SUGGESTED"
    assert suggestion["confidence"] == 0.94
    assert suggestion["semantic_mapping"] == {
        "management.ssh_enabled": True,
        "management.telnet_enabled": False,
    }
    assert suggestion["requires_human_approval"] is True

    # Interpretation proposal generation via /api/interpretations/{analysis_id}
    interp_resp = client.post(f"/api/interpretations/{analysis['analysis_id']}")
    assert interp_resp.status_code == 200
    proposals = interp_resp.json()["proposals"]
    assert len(proposals) >= 1
    proposal = proposals[0]
    assert proposal["pattern_id"] == pattern_id
    assert proposal["status"] == "NEEDS_REVIEW"
    assert proposal["confidence"] == 0.94
    assert proposal["candidate_mapping"]["management.ssh_enabled"] is True


# 3. Proposal schema validation
def test_03_proposal_schema_validation() -> None:
    # Confidence must not exceed 1.0
    with pytest.raises(ValidationError):
        CandidateMappingSuggestion(
            pattern_id="astranet-unknown-1",
            confidence=1.05,
            semantic_mapping={"management.ssh_enabled": True},
            reasoning="out of bounds confidence",
        )

    # Unsupported property rejected
    with pytest.raises(ValidationError):
        CandidateMappingSuggestion(
            pattern_id="astranet-unknown-1",
            confidence=0.9,
            semantic_mapping={"unsupported.arbitrary_prop": True},
            reasoning="unsupported property",
        )

    # Human approval requirement cannot be bypassed
    with pytest.raises(ValidationError):
        CandidateMappingSuggestion(
            pattern_id="astranet-unknown-1",
            confidence=0.9,
            semantic_mapping={"management.ssh_enabled": True},
            reasoning="bypass attempt",
            requires_human_approval=False,
        )


# 4. Proposal cannot directly create PASS
def test_04_proposal_cannot_directly_create_pass(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # Generate suggestion & interpretation proposal
    client.post(f"/api/mappings/{pattern_id}/suggest")
    client.post(f"/api/interpretations/{analysis['analysis_id']}")

    # Check that analysis bundle in DB is completely UNCHANGED
    bundle = get_analysis_bundle(analysis["analysis_id"])
    assert bundle is not None
    assert bundle["security_ir"]["normalized_properties"] == {}
    for res in bundle["response"]["results"]:
        assert res["result"] == "UNKNOWN"

    # Deterministic control engine evaluates unmapped IR to empty / no compliance
    parsed_ir = AstraNetParser.parse(CONFIG_PATH.read_text(encoding="utf-8"))
    assert DeterministicControlEngine().evaluate_all(parsed_ir, []) == []


# 5. Approve workflow
def test_05_approve_workflow(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    resp = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor-alice",
            "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    mapping = body["mapping"]
    assert mapping["version"] == 1
    assert mapping["status"] == "APPROVED"
    assert mapping["active"] is True
    assert mapping["reviewer_id"] == "auditor-alice"
    assert mapping["action"] == "APPROVE"
    assert body["compliance_impact"] == "UNCHANGED"
    assert body["pattern_status"] == "UNKNOWN"


# 6. Correct workflow
def test_06_correct_workflow(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # Initial approval
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor-alice",
            "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
        },
    )

    # Correct and approve with new mapping
    corrected_mapping = {"management.ssh_enabled": False, "management.telnet_enabled": False}
    resp = client.post(
        f"/api/mappings/{pattern_id}/correct",
        json={
            "reviewer_id": "reviewer-bob",
            "semantic_mapping": corrected_mapping,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    mapping = body["mapping"]
    assert mapping["version"] == 2
    assert mapping["status"] == "APPROVED"
    assert mapping["active"] is True
    assert mapping["reviewer_id"] == "reviewer-bob"
    assert mapping["action"] == "CORRECT_AND_APPROVE"
    assert mapping["approved_mapping"] == corrected_mapping


# 7. Reject workflow
def test_07_reject_workflow(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    resp = client.post(
        f"/api/mappings/{pattern_id}/reject",
        json={
            "reviewer_id": "auditor-charlie",
            "reason": "Unknown command does not conform to enterprise SSH spec.",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    mapping = body["mapping"]
    assert mapping["status"] == "REJECTED"
    assert mapping["active"] is False
    assert mapping["approved_mapping"] is None
    assert mapping["reviewer_id"] == "auditor-charlie"
    assert body["compliance_impact"] == "UNCHANGED"
    assert body["pattern_status"] == "UNKNOWN"


# 8. Mapping version creation
def test_08_mapping_version_creation(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # v1: approve
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "rev-1", "semantic_mapping": {"management.ssh_enabled": True}},
    )
    # v2: correct
    client.post(
        f"/api/mappings/{pattern_id}/correct",
        json={"reviewer_id": "rev-2", "semantic_mapping": {"management.ssh_enabled": False}},
    )

    versions = get_mapping_versions(pattern_id)
    assert len(versions) == 2
    assert versions[0]["version"] == 1
    assert versions[0]["status"] == "INACTIVE"
    assert versions[0]["active"] is False
    assert versions[0]["reviewer_id"] == "rev-1"

    assert versions[1]["version"] == 2
    assert versions[1]["status"] == "APPROVED"
    assert versions[1]["active"] is True
    assert versions[1]["reviewer_id"] == "rev-2"


# 9. Reviewer attribution
def test_09_reviewer_attribution(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # Missing reviewer is rejected with 422
    missing_rev = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"semantic_mapping": {"management.ssh_enabled": True}},
    )
    assert missing_rev.status_code == 422

    # Blank reviewer is rejected with 422
    blank_rev = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "   ", "semantic_mapping": {"management.ssh_enabled": True}},
    )
    assert blank_rev.status_code == 422

    # Valid reviewer attribution recorded
    valid = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "lead-auditor-99", "semantic_mapping": {"management.ssh_enabled": True}},
    )
    assert valid.status_code == 200
    assert valid.json()["mapping"]["reviewer_id"] == "lead-auditor-99"


# 10. Mapping history
def test_10_mapping_history(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": True}},
    )

    resp = client.get(f"/api/mappings/{pattern_id}/versions")
    assert resp.status_code == 200
    history = resp.json()
    assert history["pattern_id"] == pattern_id
    assert history["vendor"] == "astranet"
    assert len(history["versions"]) == 1
    assert history["versions"][0]["version"] == 1
    assert history["versions"][0]["reviewer_id"] == "auditor-1"


# 11. Re-analysis execution
def test_11_reanalysis_execution(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # Approve mapping
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False}},
    )

    # Execute reanalysis
    reanalysis_resp = client.post(f"/api/analyze/{analysis_id}/reanalyze")
    assert reanalysis_resp.status_code == 200
    child = reanalysis_resp.json()

    assert child["analysis_id"] != analysis_id
    assert child["parent_analysis_id"] == analysis_id
    assert child["reanalyzed"] is True
    assert child["mapping_version"] == 1
    assert child["message"] == "Re-analysis completed using approved mapping v1."


# 12. Original analysis immutability
def test_12_original_analysis_immutability(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # Snapshot original record
    bundle_before = get_analysis_bundle(analysis_id)
    assert bundle_before is not None

    # Approve and reanalyze
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": True}},
    )
    client.post(f"/api/analyze/{analysis_id}/reanalyze")

    # Snapshot original record after reanalysis
    bundle_after = get_analysis_bundle(analysis_id)
    assert bundle_after == bundle_before
    assert bundle_after["response"]["reanalyzed"] is False
    assert bundle_after["response"]["parent_analysis_id"] is None
    assert bundle_after["security_ir"]["normalized_properties"] == {}


# 13. Repeated re-analysis independence
def test_13_repeated_reanalysis_independence(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": True}},
    )

    # First reanalysis
    child_1 = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    # Second reanalysis
    child_2 = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()

    assert child_1["analysis_id"] != child_2["analysis_id"]
    assert child_1["parent_analysis_id"] == analysis_id
    assert child_2["parent_analysis_id"] == analysis_id

    # Chaining reanalysis on child is blocked
    chained = client.post(f"/api/analyze/{child_1['analysis_id']}/reanalyze")
    assert chained.status_code == 400


# 14. Recognized-via-approved-mapping state
def test_14_recognized_via_approved_mapping_state(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False}},
    )

    child = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    assert len(child["recognized_patterns"]) >= 1
    rec = child["recognized_patterns"][0]
    assert rec["state"] == "RECOGNIZED_VIA_APPROVED_MAPPING"
    assert rec["mapping_version"] == 1


# 15. Deterministic compliance after re-analysis
def test_15_deterministic_compliance_after_reanalysis(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # When approved mapping has ssh_enabled = True -> PASS for CTRL-001
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False}},
    )
    pass_child = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    results_pass = {r["control_id"]: r["result"] for r in pass_child["results"]}
    assert results_pass["CTRL-001"] == "PASS"

    # When corrected mapping has ssh_enabled = False -> FAIL for CTRL-001
    client.post(
        f"/api/mappings/{pattern_id}/correct",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": False, "management.telnet_enabled": False}},
    )
    fail_child = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    results_fail = {r["control_id"]: r["result"] for r in fail_child["results"]}
    assert results_fail["CTRL-001"] == "FAIL"


# 16. Evidence/provenance preservation
def test_16_evidence_provenance_preservation(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    approved = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False}},
    ).json()["mapping"]

    child = client.post(f"/api/analyze/{analysis_id}/reanalyze").json()
    evidence_items = [e for e in child["evidence"] if e["property"] == "management.ssh_enabled"]
    assert len(evidence_items) >= 1
    ev = evidence_items[0]

    assert ev["evidence_source"] == "APPROVED_MAPPING"
    assert ev["mapping_id"] == approved["mapping_id"]
    assert ev["mapping_version"] == 1
    assert ev["original_pattern"] == "guard-channel lattice-secure"
    assert ev["original_source_file"] == "unknown-pattern.conf"
    assert ev["original_line_start"] == 5
    assert ev["original_raw_excerpt"] == "guard-channel lattice-secure"


# 17. Integrity linkage (AI_PROPOSAL and MAPPING_VERSION)
def test_17_integrity_linkage(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # Generate interpretation proposal -> creates AI_PROPOSAL in ledger
    client.post(f"/api/interpretations/{analysis['analysis_id']}")

    # Approve mapping -> creates MAPPING_VERSION in ledger
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-ledger-test", "semantic_mapping": {"management.ssh_enabled": True}},
    )

    # Reanalyze -> creates ANALYSIS and EVIDENCE in ledger
    client.post(f"/api/analyze/{analysis['analysis_id']}/reanalyze")

    # Verify cryptographic integrity chain
    integrity = verify_integrity_chain()
    assert integrity["status"] == "VALID"

    # Query integrity_records table to assert records were linked
    connection = get_connection()
    try:
        rows = connection.execute("SELECT artifact_type, artifact_id, actor_id FROM integrity_records").fetchall()
        artifact_types = {r["artifact_type"] for r in rows}
        assert "AI_PROPOSAL" in artifact_types
        assert "MAPPING_VERSION" in artifact_types
        assert "ANALYSIS" in artifact_types
        assert "EVIDENCE" in artifact_types

        # Reviewer actor_id is linked to the MAPPING_VERSION record
        mapping_records = [r for r in rows if r["artifact_type"] == "MAPPING_VERSION"]
        assert any(r["actor_id"] == "auditor-ledger-test" for r in mapping_records)
    finally:
        connection.close()


# 18. Deactivation workflow and conflict detection
def test_18_deactivation_workflow_and_conflict_detection(client: TestClient) -> None:
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # Approve mapping
    app_resp = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-1", "semantic_mapping": {"management.ssh_enabled": True}},
    )
    mapping_id = app_resp.json()["mapping"]["mapping_id"]

    # Check conflicts endpoint
    conflicts_resp = client.get(f"/api/knowledge/{mapping_id}/conflicts")
    assert conflicts_resp.status_code == 200
    conflicts = conflicts_resp.json()
    assert "exact_matches" in conflicts
    assert len(conflicts["exact_matches"]) >= 1

    # Deactivate knowledge
    deact_resp = client.post(
        f"/api/knowledge/{mapping_id}/deactivate",
        json={"reviewer_id": "security-officer-1", "reason": "Revoking temporary vendor test mapping"},
    )
    assert deact_resp.status_code == 200
    assert deact_resp.json()["knowledge"]["status"] == "DEACTIVATED"

    # Reanalysis is now blocked because no active approved mapping exists
    blocked = client.post(f"/api/analyze/{analysis_id}/reanalyze")
    assert blocked.status_code == 409
    assert "active approved mapping" in blocked.json()["detail"].lower()

    # Integrity chain is still fully valid after deactivation
    assert verify_integrity_chain()["status"] == "VALID"
