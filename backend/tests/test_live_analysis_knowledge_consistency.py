"""Regression tests for emergency data / state consistency fix.

Verifies:
CASE 1: new analysis with already-known/approved pattern -> new analysis visible, no fake pending proposal.
CASE 2: new analysis with genuinely unseen pattern -> new proposal persisted, linked to correct analysis_id & pattern_id, Knowledge Review returns it.
CASE 3: Knowledge Review reflects newly created analysis without stale cache or missing linkages.
"""

from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from app.main import app


@pytest.fixture
def clean_db(tmp_path, monkeypatch):
    test_db = tmp_path / "consistency_test.db"
    from app.storage import database as db_mod
    orig_get_conn = db_mod.get_connection

    def test_get_conn(database_path=None):
        return orig_get_conn(test_db)

    monkeypatch.setattr(db_mod, "get_connection", test_get_conn)
    from app.storage import auth as auth_mod
    monkeypatch.setattr(auth_mod, "DATABASE_PATH", test_db)

    db_mod.initialize_database(test_db)
    db_mod.reset_demo_database(test_db)
    yield test_db
    db_mod.reset_demo_database(test_db)


def test_new_analysis_unseen_pattern_generates_pending_proposal(clean_db):
    """CASE 2 & 3: New analysis with genuinely unseen pattern persists proposal linked to analysis_id."""
    with TestClient(app) as client:
        # Create a genuinely unseen AstraNet config
        content = (
            b"# FICTIONAL / SYNTHETIC DEMONSTRATION DATA \xe2\x80\x94 AstraNet OS\n"
            b"astranet-device unique-router-99\n"
            b"guard-channel lattice-secure\n"
        )
        response = client.post(
            "/api/analyze",
            files={"file": ("astranet-unique-99.conf", content, "text/plain")},
        )
        assert response.status_code == 200, response.text
        data = response.json()
        analysis_id = data["analysis_id"]
        assert data["vendor"] == "astranet"
        assert len(data["unknown_patterns"]) == 1
        pattern_id = data["unknown_patterns"][0]["pattern_id"]

        # Verify Knowledge Review Queue immediately returns the proposal
        queue_res = client.get("/api/knowledge/review-queue")
        assert queue_res.status_code == 200
        queue_data = queue_res.json()
        proposals = queue_data.get("pending_proposals", [])
        assert len(proposals) == 1
        p = proposals[0]
        assert p["analysis_id"] == analysis_id
        assert p["pattern_id"] == pattern_id
        assert p["vendor"] == "astranet"
        assert p["status"] == "NEEDS_REVIEW"
        assert p["confidence"] == 0.94
        assert p["candidate_mapping"] == {"management.ssh_enabled": True, "management.telnet_enabled": False}

        # Verify Console Summary reflects the pending AI proposal
        summary_res = client.get("/api/dashboard/summary")
        assert summary_res.status_code == 200
        assert summary_res.json()["pending_ai_reviews"] == 1


def test_new_analysis_already_approved_pattern_produces_no_fake_proposal(clean_db):
    """CASE 1: New analysis with already-known/approved pattern does NOT create a fake pending proposal."""
    with TestClient(app) as client:
        content = (
            b"# FICTIONAL / SYNTHETIC DEMONSTRATION DATA \xe2\x80\x94 AstraNet OS\n"
            b"astranet-device approved-flow-router\n"
            b"guard-channel lattice-secure\n"
        )
        res1 = client.post(
            "/api/analyze",
            files={"file": ("astranet-flow.conf", content, "text/plain")},
        )
        assert res1.status_code == 200
        data1 = res1.json()
        pat_id = data1["unknown_patterns"][0]["pattern_id"]

        # Approve the proposal
        queue = client.get("/api/knowledge/review-queue").json()
        proposal_id = queue["pending_proposals"][0]["proposal_id"]
        appr_res = client.post(
            f"/api/mappings/{pat_id}/approve",
            json={
                "reviewer_id": "test-auditor",
                "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
                "proposal_id": proposal_id,
            },
        )
        assert appr_res.status_code == 200
        assert appr_res.json()["mapping"]["active"] is True

        # Now pending proposals count is 0
        queue2 = client.get("/api/knowledge/review-queue").json()
        assert len(queue2["pending_proposals"]) == 0
        assert len(queue2["active_knowledge"]) == 1

        # Upload the EXACT same configuration again
        res2 = client.post(
            "/api/analyze",
            files={"file": ("astranet-flow-copy.conf", content, "text/plain")},
        )
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["analysis_id"] != data1["analysis_id"]

        # Check queue again - STILL 0 pending proposals (no duplicate / fake proposal)
        queue3 = client.get("/api/knowledge/review-queue").json()
        assert len(queue3["pending_proposals"]) == 0
        assert len(queue3["active_knowledge"]) == 1

        # Both analyses appear in Analyses list
        analyses_res = client.get("/api/analyses")
        assert analyses_res.status_code == 200
        items = analyses_res.json()["items"]
        ids = {it["analysis_id"] for it in items}
        assert data1["analysis_id"] in ids
        assert data2["analysis_id"] in ids


def test_full_adaptive_workflow_end_to_end(clean_db):
    """Full end-to-end adaptive learning flow: UNKNOWN -> proposal -> Approve -> Re-analyze -> Deterministic."""
    with TestClient(app) as client:
        content = (
            b"# FICTIONAL / SYNTHETIC DEMONSTRATION DATA \xe2\x80\x94 AstraNet OS\n"
            b"astranet-device e2e-astranet-router\n"
            b"guard-channel lattice-secure\n"
        )
        # 1. Original analysis is UNKNOWN
        orig = client.post("/api/analyze", files={"file": ("e2e-astranet.conf", content, "text/plain")}).json()
        orig_id = orig["analysis_id"]
        assert any(r["result"] == "UNKNOWN" for r in orig["results"])
        pat_id = orig["unknown_patterns"][0]["pattern_id"]

        # 2. Knowledge Review has the proposal
        kr = client.get("/api/knowledge/review-queue").json()
        assert len(kr["pending_proposals"]) == 1
        prop_id = kr["pending_proposals"][0]["proposal_id"]

        # 3. Approve mapping using proposal_id
        appr = client.post(
            f"/api/mappings/{pat_id}/approve",
            json={
                "reviewer_id": "test-admin",
                "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False},
                "proposal_id": prop_id,
            },
        )
        assert appr.status_code == 200

        # 4. Original analysis remains UNCHANGED and UNKNOWN in database
        orig_check = client.get(f"/api/analyze/{orig_id}").json()
        assert any(r["result"] == "UNKNOWN" for r in orig_check["results"])
        assert orig_check["reanalyzed"] is False

        # 5. Re-analyze creates child analysis
        reanalysis = client.post(f"/api/analyze/{orig_id}/reanalyze")
        assert reanalysis.status_code == 200
        child = reanalysis.json()
        assert child["analysis_id"] != orig_id
        assert child["reanalyzed"] is True
        assert child["parent_analysis_id"] == orig_id
        # In child, CTRL-001 (SSH) is now deterministically evaluated as PASS
        ssh_result = next(r for r in child["results"] if r["control_id"] == "CTRL-001")
        assert ssh_result["result"] == "PASS"

        # Original analysis is STILL UNCHANGED
        orig_check2 = client.get(f"/api/analyze/{orig_id}").json()
        assert any(r["result"] == "UNKNOWN" for r in orig_check2["results"])
