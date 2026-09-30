from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.domain.interpretation import AIProposal
from app.domain.mapping import MappingStatus
from app.main import app
from app.services.interpretation_service import DemoInterpretationProvider, InterpretationUnavailable, get_interpretation_provider
from app.storage.database import get_interpretation_events, get_interpretation_proposal, reset_demo_database

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client():
    reset_demo_database()
    with TestClient(app) as value:
        yield value
    reset_demo_database()


def upload(client, name="unknown-pattern.conf", content=None):
    content = content if content is not None else (ROOT / "configs/astranet" / name).read_bytes()
    return client.post("/api/analyze", files={"file": (name, content, "text/plain")})


def test_offline_demo_provider_is_explicit_and_reproducible(client):
    original = upload(client).json()
    pattern = original["unknown_patterns"][0]
    proposal = client.post(f"/api/interpretations/{original['analysis_id']}", json={"pattern_id": pattern["pattern_id"]})
    assert proposal.status_code == 200
    payload = proposal.json()["proposals"][0]
    assert payload["interpreter_id"] == "DEMO_INTERPRETATION_PROVIDER"
    assert payload["confidence"] == 0.94
    assert payload["status"] == "NEEDS_REVIEW"
    assert payload["vendor"] == "astranet"
    assert payload["candidate_mapping"] == {"management.ssh_enabled": True, "management.telnet_enabled": False}
    assert get_interpretation_proposal(payload["proposal_id"]).analysis_id == original["analysis_id"]


def test_ai_proposal_cannot_create_pass_without_human_approval_or_reanalysis(client):
    original = upload(client).json()
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    generated = client.post(f"/api/interpretations/{original['analysis_id']}", json={"pattern_id": pattern_id}).json()
    assert {item["result"] for item in original["results"]} == {"UNKNOWN"}
    assert generated["proposals"][0]["candidate_value"] is True
    review = client.get(f"/api/interpretations/proposals/{generated['proposals'][0]['proposal_id']}")
    assert review.status_code == 200


def test_proposal_approval_links_version_but_explicit_reanalysis_determines_result(client):
    original = upload(client).json()
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    proposal = client.post(f"/api/interpretations/{original['analysis_id']}", json={"pattern_id": pattern_id}).json()["proposals"][0]
    approved = client.post(f"/api/mappings/{pattern_id}/approve", json={"reviewer_id": "auditor", "proposal_id": proposal["proposal_id"], "semantic_mapping": proposal["candidate_mapping"]})
    assert approved.status_code == 200
    assert approved.json()["mapping"]["proposal_id"] == proposal["proposal_id"]
    assert approved.json()["compliance_impact"] == "UNCHANGED"
    assert get_interpretation_proposal(proposal["proposal_id"]).status == "APPROVED"
    events = get_interpretation_events(proposal["proposal_id"])
    assert [event.action for event in events] == ["PROPOSED", "APPROVE"]
    child = client.post(f"/api/analyze/{original['analysis_id']}/reanalyze")
    assert child.status_code == 200
    results = {item["control_id"]: item["result"] for item in child.json()["results"]}
    assert results["CTRL-001"] == "PASS"
    assert results["CTRL-005"] == "PASS" and results["CTRL-006"] == "PASS"
    assert results["CTRL-002"] == "UNKNOWN"
    assert {item["result"] for item in original["results"]} == {"UNKNOWN"}


def test_correction_and_rejection_preserve_proposal_history(client):
    original = upload(client).json()
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    proposal = client.post(f"/api/interpretations/{original['analysis_id']}", json={"pattern_id": pattern_id}).json()["proposals"][0]
    corrected = client.post(f"/api/mappings/{pattern_id}/correct", json={"reviewer_id": "auditor", "proposal_id": proposal["proposal_id"], "semantic_mapping": {"management.ssh_enabled": False, "management.telnet_enabled": False}})
    assert corrected.status_code == 200
    assert corrected.json()["mapping"]["action"] == "CORRECT_AND_APPROVE"
    assert get_interpretation_events(proposal["proposal_id"])[-1].mapping == {"management.ssh_enabled": False, "management.telnet_enabled": False}

    second = upload(client, content=(ROOT / "configs/astranet/unknown-pattern.conf").read_bytes() + b"\n").json()
    second_pid = second["unknown_patterns"][0]["pattern_id"]
    second_proposal = client.post(f"/api/interpretations/{second['analysis_id']}", json={"pattern_id": second_pid}).json()["proposals"][0]
    rejected = client.post(f"/api/mappings/{second_pid}/reject", json={"reviewer_id": "auditor", "proposal_id": second_proposal["proposal_id"], "reason": "Needs more context"})
    assert rejected.status_code == 200
    assert get_interpretation_proposal(second_proposal["proposal_id"]).status == "REJECTED"
    assert client.post(f"/api/analyze/{second['analysis_id']}/reanalyze").status_code == 409


def test_proposals_are_isolated_by_analysis_identity(client):
    first = upload(client).json()
    second = upload(client, content=(ROOT / "configs/astranet/unknown-pattern.conf").read_bytes() + b"\n").json()
    first_pid = first["unknown_patterns"][0]["pattern_id"]
    second_pid = second["unknown_patterns"][0]["pattern_id"]
    first_proposal = client.post(f"/api/interpretations/{first['analysis_id']}", json={"pattern_id": first_pid}).json()["proposals"][0]
    second_proposals = client.get(f"/api/interpretations/{second['analysis_id']}").json()["proposals"]
    assert not any(p["analysis_id"] == first["analysis_id"] for p in second_proposals)
    assert not any(p["proposal_id"] == first_proposal["proposal_id"] for p in second_proposals)
    assert first_proposal["analysis_id"] == first["analysis_id"]
    assert first_proposal["pattern_id"] != second_pid


def test_proposal_contract_rejects_invalid_confidence_and_non_boolean_claims():
    with pytest.raises(ValidationError):
        AIProposal(
            proposal_id="p", analysis_id="a", pattern_id="x", vendor="astranet", pattern_signature="s",
            source_context="context", candidate_property="management.ssh_enabled", candidate_value=True,
            candidate_mapping={"management.ssh_enabled": 1}, confidence=1.1, explanation="x",
            interpreter_id="demo", interpreter_version="1", created_at="2026-01-01T00:00:00Z", updated_at="2026-01-01T00:00:00Z",
        )


def test_unknown_pattern_has_no_unsafe_external_provider():
    assert isinstance(get_interpretation_provider(), DemoInterpretationProvider)
    with pytest.raises(InterpretationUnavailable):
        DemoInterpretationProvider().interpret(
            __import__("app.domain.security_ir", fromlist=["UnknownPattern"]).UnknownPattern(pattern_id="x", raw_pattern="other", source_file="x.conf"),
            vendor="astranet", analysis_id="a",
        )
