from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.domain.control_engine import DeterministicControlEngine
from app.domain.mapping import CandidateMappingSuggestion
from app.main import app
from app.parsers.astranet import AstraNetParser
from app.services.ai_suggestion_service import LocalDemoSuggestionService, SuggestionUnavailable
from app.storage.database import get_connection, get_mapping_versions, initialize_database


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


def analyze_astranet(client: TestClient) -> str:
    response = client.post(
        "/api/analyze",
        files={"file": (CONFIG_PATH.name, CONFIG_PATH.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    return response.json()["unknown_patterns"][0]["pattern_id"]


def suggestion_payload() -> dict[str, bool]:
    return {
        "management.ssh_enabled": True,
        "management.telnet_enabled": False,
    }


def test_unknown_pattern_can_request_a_controlled_suggestion(client: TestClient) -> None:
    pattern_id = analyze_astranet(client)
    response = client.post(f"/api/mappings/{pattern_id}/suggest")

    assert response.status_code == 200
    payload = response.json()
    assert payload["pattern_id"] == pattern_id
    assert payload["status"] == "SUGGESTED"
    assert payload["confidence"] == 0.94
    assert payload["semantic_mapping"] == suggestion_payload()
    assert payload["requires_human_approval"] is True


def test_candidate_mapping_schema_rejects_invalid_output() -> None:
    with pytest.raises(ValidationError):
        CandidateMappingSuggestion(
            pattern_id="astranet-unknown-5",
            confidence=1.1,
            semantic_mapping=suggestion_payload(),
            reasoning="invalid confidence",
        )

    with pytest.raises(ValidationError):
        CandidateMappingSuggestion(
            pattern_id="astranet-unknown-5",
            confidence=0.9,
            semantic_mapping={"arbitrary.property": True},
            reasoning="unsupported property",
        )

    with pytest.raises(ValidationError):
        CandidateMappingSuggestion(
            pattern_id="astranet-unknown-5",
            confidence=0.9,
            semantic_mapping=suggestion_payload(),
            reasoning="approval bypass",
            requires_human_approval=False,
        )


def test_controlled_adapter_does_not_guess_for_other_patterns() -> None:
    pattern = AstraNetParser.parse(CONFIG_PATH.read_text(encoding="utf-8")).unknown_patterns[0]
    altered = pattern.model_copy(update={"raw_pattern": "guard-channel unfamiliar"})
    with pytest.raises(SuggestionUnavailable):
        LocalDemoSuggestionService().suggest(altered, vendor="astranet")


def test_approval_creates_version_one_and_requires_human_identity(client: TestClient) -> None:
    pattern_id = analyze_astranet(client)
    candidate = client.post(f"/api/mappings/{pattern_id}/suggest").json()

    missing_reviewer = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"semantic_mapping": candidate["semantic_mapping"]},
    )
    assert missing_reviewer.status_code == 422

    response = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "demo-reviewer",
            "semantic_mapping": candidate["semantic_mapping"],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    mapping = payload["mapping"]
    assert mapping["version"] == 1
    assert mapping["status"] == "APPROVED"
    assert mapping["active"] is True
    assert mapping["reviewer_id"] == "demo-reviewer"
    assert mapping["action"] == "APPROVE"
    assert payload["pattern_status"] == "UNKNOWN"
    assert payload["compliance_impact"] == "UNCHANGED"

    history = get_mapping_versions(pattern_id)
    assert len(history) == 1
    assert history[0]["version"] == 1


def test_correction_creates_new_active_version_and_preserves_previous(client: TestClient) -> None:
    pattern_id = analyze_astranet(client)
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "reviewer-one", "semantic_mapping": suggestion_payload()},
    )
    corrected = {"management.ssh_enabled": False, "management.telnet_enabled": False}
    response = client.post(
        f"/api/mappings/{pattern_id}/correct",
        json={"reviewer_id": "reviewer-two", "semantic_mapping": corrected},
    )

    assert response.status_code == 200
    assert response.json()["mapping"]["version"] == 2
    assert response.json()["mapping"]["action"] == "CORRECT_AND_APPROVE"

    history = client.get(f"/api/mappings/{pattern_id}/versions").json()["versions"]
    assert len(history) == 2
    assert history[0]["status"] == "INACTIVE"
    assert history[0]["active"] is False
    assert history[0]["approved_mapping"] == suggestion_payload()
    assert history[1]["status"] == "APPROVED"
    assert history[1]["active"] is True
    assert history[1]["approved_mapping"] == corrected


def test_reject_creates_inactive_version_and_pattern_stays_unknown(client: TestClient) -> None:
    pattern_id = analyze_astranet(client)
    response = client.post(
        f"/api/mappings/{pattern_id}/reject",
        json={"reviewer_id": "demo-reviewer", "reason": "Not sufficiently established."},
    )

    assert response.status_code == 200
    mapping = response.json()["mapping"]
    assert mapping["status"] == "REJECTED"
    assert mapping["active"] is False
    assert mapping["approved_mapping"] is None
    assert response.json()["pattern_status"] == "UNKNOWN"
    assert response.json()["compliance_impact"] == "UNCHANGED"


def test_mapping_history_and_review_endpoint_return_stored_state(client: TestClient) -> None:
    pattern_id = analyze_astranet(client)
    assert client.get(f"/api/mappings/unknown/{pattern_id}").status_code == 200
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "demo-reviewer", "semantic_mapping": suggestion_payload()},
    )
    review = client.get(f"/api/mappings/unknown/{pattern_id}").json()
    history = client.get(f"/api/mappings/{pattern_id}/versions").json()

    assert review["vendor"] == "astranet"
    assert review["pattern"]["raw_pattern"] == "guard-channel lattice-secure"
    assert review["latest_mapping"]["version"] == 1
    assert len(history["versions"]) == 1


def test_approval_does_not_create_compliance_or_modify_security_ir(client: TestClient) -> None:
    pattern_id = analyze_astranet(client)
    security_ir = AstraNetParser.parse(CONFIG_PATH.read_text(encoding="utf-8"))
    before = security_ir.model_dump(mode="json")
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "demo-reviewer", "semantic_mapping": suggestion_payload()},
    )
    after = security_ir.model_dump(mode="json")

    assert after == before
    assert security_ir.normalized_properties == {}
    assert DeterministicControlEngine().evaluate_all(security_ir, []) == []

    # The persisted analysis is still authoritative until a later re-analysis.
    analysis = client.post(
        "/api/analyze",
        files={"file": (CONFIG_PATH.name, CONFIG_PATH.read_bytes(), "text/plain")},
    )
    assert {item["result"] for item in analysis.json()["results"]} == {"UNKNOWN"}


def test_invalid_api_mapping_property_is_rejected_without_storage(client: TestClient) -> None:
    pattern_id = analyze_astranet(client)
    response = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={
            "reviewer_id": "demo-reviewer",
            "semantic_mapping": {"arbitrary.property": True},
        },
    )
    assert response.status_code == 422
    assert get_mapping_versions(pattern_id) == []


def test_missing_pattern_is_safe(client: TestClient) -> None:
    response = client.post("/api/mappings/not-found/suggest")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
