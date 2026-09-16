import json
from pathlib import Path

from fastapi.testclient import TestClient
from app.main import app
from app.domain.integrity import artifact_hash, canonical_json
from app.storage.database import (
    append_integrity_record,
    get_connection,
    initialize_database,
    verify_integrity_chain,
    verify_integrity_record,
    save_mapping_version,
)


def test_canonicalization_and_hash_are_independent_of_json_key_order():
    first = {"z": [2, {"b": True, "a": None}], "a": "value"}
    second = {"a": "value", "z": [2, {"a": None, "b": True}]}
    assert canonical_json(first) == canonical_json(second)
    assert artifact_hash("ANALYSIS", "analysis-1", first)[0] == artifact_hash("ANALYSIS", "analysis-1", second)[0]


def test_configuration_fingerprint_is_retained_and_artifact_tampering_is_detected(tmp_path):
    database = tmp_path / "integrity.db"
    initialize_database(database)
    configuration = {"configuration_id": "config-1", "device_id": "device-1", "content_sha256": "a" * 64, "source_filename": "safe.conf"}
    with get_connection(database) as connection:
        connection.execute("INSERT INTO devices VALUES (?, ?)", ("device-1", json.dumps({"device_id": "device-1"})))
        connection.execute("INSERT INTO configurations VALUES (?, ?, ?, ?)", ("config-1", "device-1", configuration["content_sha256"], json.dumps(configuration)))
        connection.commit()
    append_integrity_record("CONFIGURATION", "config-1", {"configuration": configuration, "content_sha256": configuration["content_sha256"]}, database_path=database)
    assert verify_integrity_record("CONFIGURATION", "config-1", database)["status"] == "VALID"
    with get_connection(database) as connection:
        connection.execute("UPDATE configurations SET record_json = ? WHERE configuration_id = ?", (json.dumps(configuration | {"source_filename": "changed.conf"}), "config-1"))
        connection.commit()
    assert verify_integrity_record("CONFIGURATION", "config-1", database)["status"] == "INVALID"


def test_append_only_chain_detects_record_mutation_and_truncation(tmp_path):
    database = tmp_path / "chain.db"
    initialize_database(database)
    first = append_integrity_record("AI_PROPOSAL", "proposal-1", {"candidate": True}, actor_id="reviewer-1", database_path=database)
    second = append_integrity_record("MAPPING_VERSION", "mapping-1:v1", {"approved": True}, actor_id="reviewer-1", database_path=database)
    assert verify_integrity_chain(database)["status"] == "VALID"
    with get_connection(database) as connection:
        connection.execute("UPDATE integrity_records SET actor_id = ? WHERE integrity_record_id = ?", ("attacker", first["integrity_record_id"]))
        connection.commit()
    assert verify_integrity_chain(database)["status"] == "INVALID"
    # A missing historical record also breaks the previous-hash link/state anchor.
    with get_connection(database) as connection:
        connection.execute("DELETE FROM integrity_records WHERE integrity_record_id = ?", (second["integrity_record_id"],))
        connection.commit()
    assert verify_integrity_chain(database)["status"] == "INVALID"


def test_canonical_snapshot_and_mapping_versions_are_independently_verifiable(tmp_path):
    database = tmp_path / "immutable-ledger.db"
    initialize_database(database)
    artifact = append_integrity_record("REPORT", "report-1", {"analysis_id": "analysis-1"}, database_path=database)
    assert verify_integrity_record("REPORT", "report-1", database)["status"] == "VALID"
    with get_connection(database) as connection:
        connection.execute("UPDATE integrity_records SET canonical_payload = ? WHERE integrity_record_id = ?", ("{}", artifact["integrity_record_id"]))
        connection.commit()
    assert verify_integrity_record("REPORT", "report-1", database)["status"] == "INVALID"
    assert verify_integrity_chain(database)["status"] == "INVALID"

    # Use a fresh ledger for the independent immutable-version sequence.
    database = tmp_path / "mapping-versions.db"
    initialize_database(database)
    common = dict(pattern_id="pattern-1", vendor="astranet", pattern_signature="signature", proposed_mapping={"management.ssh_enabled": True}, approved_mapping={"management.ssh_enabled": True}, status="APPROVED", reviewer_id="reviewer", action="APPROVE")
    v1 = save_mapping_version(**common, database_path=database)
    assert verify_integrity_record("MAPPING_VERSION", f"{v1['mapping_id']}:v1", database)["status"] == "VALID"
    v2 = save_mapping_version(**(common | {"action": "CORRECT_AND_APPROVE"}), database_path=database)
    assert verify_integrity_record("MAPPING_VERSION", f"{v1['mapping_id']}:v1", database)["status"] == "VALID"
    assert verify_integrity_record("MAPPING_VERSION", f"{v2['mapping_id']}:v2", database)["status"] == "VALID"
    with get_connection(database) as connection:
        connection.execute("UPDATE mapping_versions SET approved_mapping_json = ? WHERE mapping_id = ? AND version = 1", (json.dumps({"management.ssh_enabled": False}), v1["mapping_id"]))
        connection.commit()
    assert verify_integrity_record("MAPPING_VERSION", f"{v1['mapping_id']}:v1", database)["status"] == "INVALID"


def test_integrity_api_exposes_structured_verification_for_new_analysis():
    root = Path(__file__).resolve().parents[2]
    with TestClient(app) as client:
        response = client.post("/api/analyze", files={"file": ("compliant.conf", (root / "configs/cisco/compliant.conf").read_bytes(), "text/plain")})
        assert response.status_code == 200
        analysis_id = response.json()["analysis_id"]
        artifact = client.post(f"/api/integrity/ANALYSIS/{analysis_id}/verify")
        assert artifact.status_code == 200
        assert artifact.json()["status"] == "VALID"
        evidence = client.get(f"/api/integrity/EVIDENCE/{analysis_id}:evidence:0")
        assert evidence.status_code == 200 and evidence.json()["status"] == "VALID"
        assert client.get("/api/integrity/chain").json()["status"] == "VALID"
