from datetime import datetime, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.domain.interpretation import AIProposal
from app.domain.mapping import MappingStatus
from app.main import app
from app.storage.database import (
    get_all_interpretation_proposals,
    get_analysis_bundle,
    get_connection,
    get_interpretation_proposal,
    get_interpretation_proposals,
    get_latest_mapping,
    initialize_database,
    list_knowledge,
    reset_demo_database,
    save_interpretation_proposal,
)
from scripts import seed_demo

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "configs" / "astranet" / "unknown-pattern.conf"


@pytest.fixture(autouse=True)
def isolate_records():
    initialize_database()
    conn = get_connection()
    try:
        conn.execute("DELETE FROM simulation_results")
        conn.execute("DELETE FROM interpretation_events")
        conn.execute("DELETE FROM interpretation_proposals")
        conn.execute("DELETE FROM mapping_approvals")
        conn.execute("DELETE FROM mapping_versions")
        conn.execute("DELETE FROM mappings")
        conn.execute("DELETE FROM analysis_results")
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _upload_astranet(client: TestClient) -> dict:
    response = client.post(
        "/api/analyze",
        files={"file": (CONFIG_PATH.name, CONFIG_PATH.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    return response.json()


# 1. Proposal stores exact pattern_id
def test_01_proposal_stores_exact_pattern_id(client: TestClient):
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    assert suggest_resp.status_code == 200
    proposal_id = suggest_resp.json()["proposal_id"]
    assert proposal_id is not None

    proposal = get_interpretation_proposal(proposal_id)
    assert proposal is not None
    assert proposal.pattern_id == pattern_id
    assert proposal.vendor == "astranet"


# 2. Proposal stores/or resolves original analysis_id
def test_02_proposal_stores_and_resolves_original_analysis_id(client: TestClient):
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    proposal_id = suggest_resp.json()["proposal_id"]

    proposal = get_interpretation_proposal(proposal_id)
    assert proposal is not None
    assert proposal.analysis_id == analysis_id

    bundle = get_analysis_bundle(proposal.analysis_id)
    assert bundle is not None
    assert bundle["response"]["analysis_id"] == analysis_id


# 3. Approve resolves the exact persisted unknown pattern
def test_03_approve_resolves_exact_persisted_unknown_pattern(client: TestClient):
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    proposal_id = suggest_resp.json()["proposal_id"]

    approve_resp = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor-alice",
            "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
            "proposal_id": proposal_id,
        },
    )
    assert approve_resp.status_code == 200
    mapping = approve_resp.json()["mapping"]
    assert mapping["pattern_id"] == pattern_id
    assert mapping["identity"]["source_analysis_id"] == analysis["analysis_id"]


# 4. Approve creates v1 successfully
def test_04_approve_creates_v1_successfully(client: TestClient):
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    proposal_id = suggest_resp.json()["proposal_id"]

    approve_resp = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor-alice",
            "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
            "proposal_id": proposal_id,
        },
    )
    assert approve_resp.status_code == 200
    data = approve_resp.json()
    assert data["mapping"]["version"] == 1
    assert data["mapping"]["status"] == "APPROVED"
    assert data["mapping"]["active"] is True
    assert data["mapping"]["reviewer_id"] == "auditor-alice"

    # Proposal transitioned to APPROVED
    updated_proposal = get_interpretation_proposal(proposal_id)
    assert updated_proposal is not None
    assert updated_proposal.status == "APPROVED"


# 5. Approval alone leaves original analysis UNKNOWN
def test_05_approval_alone_leaves_original_analysis_unknown(client: TestClient):
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    proposal_id = suggest_resp.json()["proposal_id"]

    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor-alice",
            "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
            "proposal_id": proposal_id,
        },
    )

    bundle = get_analysis_bundle(analysis_id)
    assert bundle is not None
    assert bundle["security_ir"]["normalized_properties"] == {}
    unknown_results = [r for r in bundle["response"]["results"] if r["result"] == "UNKNOWN"]
    assert len(unknown_results) > 0


# 6. Correct-and-approve resolves the same authoritative pattern
def test_06_correct_and_approve_resolves_same_authoritative_pattern(client: TestClient):
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    proposal_id = suggest_resp.json()["proposal_id"]

    correct_resp = client.post(
        f"/api/mappings/{pattern_id}/correct",
        json={
            "reviewer_id": "auditor-bob",
            "semantic_mapping": {"management.ssh_enabled": False, "management.telnet_enabled": False},
            "proposal_id": proposal_id,
        },
    )
    assert correct_resp.status_code == 200
    mapping = correct_resp.json()["mapping"]
    assert mapping["version"] == 1
    assert mapping["status"] == "APPROVED"
    assert mapping["action"] == "CORRECT_AND_APPROVE"
    assert mapping["reviewer_id"] == "auditor-bob"
    assert mapping["approved_mapping"]["management.ssh_enabled"] is False
    assert mapping["identity"]["source_analysis_id"] == analysis["analysis_id"]


# 7. Reject leaves pattern unresolved
def test_07_reject_leaves_pattern_unresolved(client: TestClient):
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    proposal_id = suggest_resp.json()["proposal_id"]

    reject_resp = client.post(
        f"/api/mappings/{pattern_id}/reject",
        json={
            "reviewer_id": "auditor-charlie",
            "reason": "Not approved for production use.",
            "proposal_id": proposal_id,
        },
    )
    assert reject_resp.status_code == 200
    data = reject_resp.json()
    assert data["mapping"]["status"] == "REJECTED"
    assert data["mapping"]["active"] is False

    proposal = get_interpretation_proposal(proposal_id)
    assert proposal is not None
    assert proposal.status == "REJECTED"


# 8. Missing/stale pattern linkage returns a safe explicit error
def test_08_missing_or_stale_pattern_linkage_returns_safe_explicit_error(client: TestClient):
    analysis = _upload_astranet(client)
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    # 8a: Nonexistent proposal_id
    resp = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor",
            "semantic_mapping": {"management.ssh_enabled": True},
            "proposal_id": "proposal-nonexistent-1234",
        },
    )
    assert resp.status_code == 404
    assert "proposal was not found" in resp.json()["detail"].lower()

    # 8b: Proposal pointing to non-existent analysis
    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    real_prop = get_interpretation_proposal(suggest_resp.json()["proposal_id"])
    assert real_prop is not None
    fake_proposal = real_prop.model_copy(update={
        "proposal_id": "proposal-stale-test",
        "analysis_id": str(uuid4()),
    })
    save_interpretation_proposal(fake_proposal)
    resp = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor",
            "semantic_mapping": {"management.ssh_enabled": True},
            "proposal_id": "proposal-stale-test",
        },
    )
    assert resp.status_code == 404
    assert "not found in a persisted analysis" in resp.json()["detail"].lower()

    # 8c: Proposal pattern mismatch
    resp = client.post(
        "/api/mappings/different-pattern-id/approve",
        json={
            "reviewer_id": "auditor",
            "semantic_mapping": {"management.ssh_enabled": True},
            "proposal_id": "proposal-stale-test",
        },
    )
    assert resp.status_code == 409
    assert "identity does not match" in resp.json()["detail"].lower()


# 9. Seed_demo does not accumulate duplicate proposals across repeated runs
def test_09_seed_demo_does_not_accumulate_duplicate_proposals():
    # Run seed_demo twice
    seed_demo.main()
    first_pending = [p for p in get_all_interpretation_proposals() if p.status == "NEEDS_REVIEW"]
    first_active = list_knowledge(status="ACTIVE")

    seed_demo.main()
    second_pending = [p for p in get_all_interpretation_proposals() if p.status == "NEEDS_REVIEW"]
    second_active = list_knowledge(status="ACTIVE")

    assert len(second_pending) == 1
    assert len(second_active) == 1
    assert len(first_pending) == len(second_pending)
    assert len(first_active) == len(second_active)


# 10. Reset + seed produces deterministic proposal/analysis linkage
def test_10_reset_and_seed_produces_deterministic_proposal_analysis_linkage():
    seed_demo.main()
    pending = [p for p in get_all_interpretation_proposals() if p.status == "NEEDS_REVIEW"]
    assert len(pending) == 1
    proposal = pending[0]

    bundle = get_analysis_bundle(proposal.analysis_id)
    assert bundle is not None
    assert bundle["response"]["analysis_id"] == proposal.analysis_id
    assert any(p["pattern_id"] == proposal.pattern_id for p in bundle["response"]["unknown_patterns"])


# 11. Re-analysis works after successful approval
def test_11_reanalysis_works_after_successful_approval(client: TestClient):
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    proposal_id = suggest_resp.json()["proposal_id"]

    approve_resp = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor-alice",
            "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
            "proposal_id": proposal_id,
        },
    )
    assert approve_resp.status_code == 200

    reanalysis_resp = client.post(f"/api/analyze/{analysis_id}/reanalyze")
    assert reanalysis_resp.status_code == 200
    child = reanalysis_resp.json()
    assert child["reanalyzed"] is True
    assert child["parent_analysis_id"] == analysis_id
    results_map = {r["control_id"]: r["result"] for r in child["results"]}
    assert results_map["CTRL-001"] == "PASS"


# 12. Original analysis remains immutable
def test_12_original_analysis_remains_immutable(client: TestClient):
    analysis = _upload_astranet(client)
    analysis_id = analysis["analysis_id"]
    pattern_id = analysis["unknown_patterns"][0]["pattern_id"]

    bundle_before = get_analysis_bundle(analysis_id)
    assert bundle_before is not None

    suggest_resp = client.post(f"/api/mappings/{pattern_id}/suggest")
    proposal_id = suggest_resp.json()["proposal_id"]

    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "auditor-alice",
            "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
            "proposal_id": proposal_id,
        },
    )
    client.post(f"/api/analyze/{analysis_id}/reanalyze")

    bundle_after = get_analysis_bundle(analysis_id)
    assert bundle_after == bundle_before
