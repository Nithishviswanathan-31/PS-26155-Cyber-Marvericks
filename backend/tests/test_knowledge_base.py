from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.storage.database import (
    find_knowledge,
    get_analysis_bundle,
    get_connection,
    record_knowledge_usage,
    reset_demo_database,
    save_mapping_version,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client():
    reset_demo_database()
    with TestClient(app) as value:
        yield value
    reset_demo_database()


def upload_unknown(client, name="unknown-pattern.conf"):
    return client.post("/api/analyze", files={"file": (name, (ROOT / "configs/astranet/unknown-pattern.conf").read_bytes(), "text/plain")}).json()


def mapping_payload(value=True):
    return {"management.ssh_enabled": value, "management.telnet_enabled": False}


def approve(client, analysis, value=True):
    pattern = analysis["unknown_patterns"][0]["pattern_id"]
    proposal = client.post(f"/api/mappings/{pattern}/suggest").json()["proposal_id"]
    response = client.post(f"/api/mappings/{pattern}/approve", json={"reviewer_id": "reviewer", "semantic_mapping": mapping_payload(value), "proposal_id": proposal})
    assert response.status_code == 200
    return response.json()["mapping"]


def test_knowledge_projection_links_proposal_and_preserves_compliance_boundary(client):
    analysis = upload_unknown(client)
    before = get_analysis_bundle(analysis["analysis_id"])
    mapping = approve(client, analysis)
    entry = client.get(f"/api/knowledge/{mapping['mapping_id']}").json()
    assert entry["knowledge_id"] == mapping["mapping_id"]
    assert entry["status"] == "ACTIVE" and entry["originating_proposal_id"]
    assert entry["normalized_context"] and entry["approved_mapping"] == mapping_payload()
    # Knowledge is a reference only. It cannot mutate the source analysis.
    assert get_analysis_bundle(analysis["analysis_id"]) == before
    assert {item["result"] for item in before["response"]["results"]} == {"UNKNOWN"}


def test_exact_related_and_conflicting_knowledge_are_explicit_and_vendor_isolated(client):
    first = upload_unknown(client)
    approve(client, first, True)
    second = upload_unknown(client, "other.conf")
    knowledge = client.get(f"/api/mappings/unknown/{second['unknown_patterns'][0]['pattern_id']}/knowledge").json()
    assert knowledge["exact_matches"] and not knowledge["related_knowledge"]
    # Directly create a second lineage with the same exact identity but a different value.
    original = knowledge["exact_matches"][0]
    identity = {"context": original["normalized_context"], "target_properties": ["management.ssh_enabled"], "source_pattern": original["source_pattern"], "source_location": {"source_file": "fixture.conf"}, "source_analysis_id": first["analysis_id"]}
    save_mapping_version(pattern_id="isolated-conflict", vendor="astranet", pattern_signature=original["pattern_signature"], proposed_mapping={"management.ssh_enabled": False}, approved_mapping={"management.ssh_enabled": False}, status="APPROVED", reviewer_id="reviewer-two", action="APPROVE", identity=identity)
    related_identity = {**identity, "context": "different exact parser context"}
    save_mapping_version(pattern_id="isolated-related", vendor="astranet", pattern_signature=original["pattern_signature"], proposed_mapping={"management.ssh_enabled": True}, approved_mapping={"management.ssh_enabled": True}, status="APPROVED", reviewer_id="reviewer-three", action="APPROVE", identity=related_identity)
    classification = find_knowledge("astranet", original["pattern_signature"], original["normalized_context"])
    assert len(classification["conflicts"]) == 2
    assert len(classification["related_knowledge"]) == 1
    assert find_knowledge("cisco_iosxe", original["pattern_signature"], original["normalized_context"])["exact_matches"] == []


def test_deactivation_keeps_history_blocks_reanalysis_and_usage_is_audit_only(client):
    analysis = upload_unknown(client)
    mapping = approve(client, analysis)
    before = get_analysis_bundle(analysis["analysis_id"])
    child = client.post(f"/api/analyze/{analysis['analysis_id']}/reanalyze")
    assert child.status_code == 200
    response = client.post(f"/api/knowledge/{mapping['mapping_id']}/deactivate", json={"reviewer_id": "reviewer", "reason": "superseded"})
    assert response.status_code == 200 and response.json()["knowledge"]["status"] == "DEACTIVATED"
    detail = client.get(f"/api/knowledge/{mapping['mapping_id']}").json()
    assert detail["usage"]["applied_count"] == 1 and detail["history"]
    assert client.post(f"/api/analyze/{analysis['analysis_id']}/reanalyze").status_code == 409
    assert get_analysis_bundle(analysis["analysis_id"]) == before


def test_knowledge_api_filters_and_does_not_leak_across_batch_items(client):
    batch = client.post("/api/batches/analyze", files=[("files", ("one.conf", (ROOT / "configs/astranet/unknown-pattern.conf").read_bytes(), "text/plain")), ("files", ("two.conf", (ROOT / "configs/astranet/unknown-pattern.conf").read_bytes(), "text/plain"))]).json()
    items = client.get(f"/api/batches/{batch['batch_id']}/items").json()
    first = client.get(f"/api/analyses/{items[0]['analysis_id']}")
    # Batch upload remains isolated; mapping retrieval itself is informational.
    assert items[0]["analysis_id"] != items[1]["analysis_id"]
    assert client.get("/api/knowledge?vendor=cisco_iosxe").json() == []
