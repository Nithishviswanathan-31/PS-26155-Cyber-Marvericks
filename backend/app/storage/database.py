import sqlite3
from collections.abc import Generator
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..config import DATABASE_PATH
from ..domain.inventory import Device, Configuration, ConfigurationHistory, DeviceAnalysisHistory
from ..domain.batch import BatchAnalysis, BatchItem
from ..domain.interpretation import AIProposal, InterpretationEvent
from ..domain.integrity import ALGORITHM, SCHEMA_VERSION, artifact_hash, canonical_json, ledger_hash


def get_connection(database_path: Path = DATABASE_PATH) -> sqlite3.Connection:
    """Open the local SQLite database used by the emergency demo."""

    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(database_path: Path = DATABASE_PATH) -> None:
    """Initialize the local analysis and mapping tables used by the demo."""

    connection = get_connection(database_path)
    try:
        connection.execute("SELECT 1")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_results (
                analysis_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                vendor TEXT NOT NULL,
                response_json TEXT NOT NULL,
                security_ir_json TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        analysis_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(analysis_results)").fetchall()
        }
        if "security_ir_json" not in analysis_columns:
            connection.execute("ALTER TABLE analysis_results ADD COLUMN security_ir_json TEXT")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mappings (
                mapping_id TEXT PRIMARY KEY,
                pattern_id TEXT NOT NULL UNIQUE,
                vendor TEXT NOT NULL,
                pattern_signature TEXT NOT NULL,
                current_version INTEGER,
                active INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mapping_versions (
                mapping_id TEXT NOT NULL,
                pattern_id TEXT NOT NULL,
                vendor TEXT NOT NULL,
                pattern_signature TEXT NOT NULL,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                proposed_mapping_json TEXT NOT NULL,
                approved_mapping_json TEXT,
                reviewer_id TEXT,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (mapping_id, version),
                FOREIGN KEY (mapping_id) REFERENCES mappings(mapping_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mapping_approvals (
                approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
                mapping_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                action TEXT NOT NULL,
                reviewer_id TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (mapping_id) REFERENCES mappings(mapping_id)
            )
            """
        )
        version_columns = {row["name"] for row in connection.execute("PRAGMA table_info(mapping_versions)")}
        if "identity_json" not in version_columns:
            connection.execute("ALTER TABLE mapping_versions ADD COLUMN identity_json TEXT")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS simulation_results (
                simulation_id TEXT PRIMARY KEY,
                parent_analysis_id TEXT NOT NULL,
                remediation_id TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, record_json TEXT NOT NULL)")
        connection.execute("CREATE TABLE IF NOT EXISTS configurations (configuration_id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(device_id), content_sha256 TEXT NOT NULL, record_json TEXT NOT NULL)")
        connection.execute("CREATE INDEX IF NOT EXISTS configuration_fingerprint_idx ON configurations(content_sha256)")
        connection.execute("CREATE TABLE IF NOT EXISTS analysis_configurations (analysis_id TEXT PRIMARY KEY REFERENCES analysis_results(analysis_id), configuration_id TEXT NOT NULL REFERENCES configurations(configuration_id))")
        connection.execute("CREATE TABLE IF NOT EXISTS batches (batch_id TEXT PRIMARY KEY, record_json TEXT NOT NULL)")
        connection.execute("CREATE TABLE IF NOT EXISTS batch_items (batch_item_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batches(batch_id), record_json TEXT NOT NULL)")
        connection.execute("CREATE TABLE IF NOT EXISTS interpretation_proposals (proposal_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, pattern_id TEXT NOT NULL, record_json TEXT NOT NULL)")
        connection.execute("CREATE TABLE IF NOT EXISTS interpretation_events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, proposal_id TEXT NOT NULL REFERENCES interpretation_proposals(proposal_id), record_json TEXT NOT NULL)")
        mapping_columns = {row["name"] for row in connection.execute("PRAGMA table_info(mapping_versions)")}
        if "proposal_id" not in mapping_columns:
            connection.execute("ALTER TABLE mapping_versions ADD COLUMN proposal_id TEXT")
        # Usage is deliberately kept outside immutable mapping-version payloads.
        # It is audit metadata only and is never read by the control engine.
        connection.execute(
            "CREATE TABLE IF NOT EXISTS knowledge_usage (mapping_id TEXT NOT NULL, version INTEGER NOT NULL, referenced_count INTEGER NOT NULL DEFAULT 0, applied_count INTEGER NOT NULL DEFAULT 0, last_referenced_at TEXT, last_applied_at TEXT, PRIMARY KEY (mapping_id, version), FOREIGN KEY (mapping_id, version) REFERENCES mapping_versions(mapping_id, version))"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS integrity_records (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                integrity_record_id TEXT NOT NULL UNIQUE,
                artifact_type TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                previous_hash TEXT,
                record_hash TEXT NOT NULL UNIQUE,
                canonical_payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                actor_id TEXT,
                algorithm TEXT NOT NULL,
                schema_version TEXT NOT NULL
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS integrity_artifact_idx ON integrity_records(artifact_type, artifact_id, sequence DESC)")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS integrity_ledger_state (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), record_count INTEGER NOT NULL, last_hash TEXT, updated_at TEXT NOT NULL)"
        )
        connection.execute("CREATE TABLE IF NOT EXISTS reports (report_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, report_version INTEGER NOT NULL, generated_at TEXT NOT NULL, generated_by TEXT, integrity_record_id TEXT, metadata_json TEXT NOT NULL, UNIQUE(analysis_id, report_version))")
        connection.execute(
            "INSERT OR IGNORE INTO integrity_ledger_state(singleton, record_count, last_hash, updated_at) VALUES (1, 0, NULL, ?)",
            (datetime.now(timezone.utc).isoformat(),),
        )
        connection.commit()
    finally:
        connection.close()


def reset_demo_database(database_path: Path = DATABASE_PATH) -> dict[str, int]:
    """Clear only local demo records while preserving the SQLite schema.

    The API route additionally blocks this operation when APP_ENV is production.
    Keeping the database path injectable makes this operation safe to test.
    """

    initialize_database(database_path)
    tables = (
        "analysis_configurations",
        "configurations",
        "devices",
        "simulation_results",
        "mapping_approvals",
        "knowledge_usage",
        "mapping_versions",
        "mappings",
        "batch_items",
        "batches",
        "interpretation_events",
        "interpretation_proposals",
        "analysis_results",
        "integrity_records",
        "integrity_ledger_state",
        "reports",
    )
    connection = get_connection(database_path)
    try:
        deleted: dict[str, int] = {}
        for table in tables:
            cursor = connection.execute(f"DELETE FROM {table}")
            deleted[table] = cursor.rowcount
        connection.execute(
            "INSERT INTO integrity_ledger_state(singleton, record_count, last_hash, updated_at) VALUES (1, 0, NULL, ?)",
            (datetime.now(timezone.utc).isoformat(),),
        )
        connection.commit()
        return deleted
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def append_integrity_record(
    artifact_type: str,
    artifact_id: str,
    payload: dict[str, Any],
    *,
    actor_id: str | None = None,
    connection: sqlite3.Connection | None = None,
    database_path: Path = DATABASE_PATH,
) -> dict[str, Any]:
    """Append an immutable ledger entry. Callers may provide their write transaction."""
    owns_connection = connection is None
    if owns_connection:
        initialize_database(database_path)
        connection = get_connection(database_path)
        connection.execute("BEGIN IMMEDIATE")
    assert connection is not None
    try:
        content_hash, canonical_payload = artifact_hash(artifact_type, artifact_id, payload)
        state = connection.execute("SELECT record_count, last_hash FROM integrity_ledger_state WHERE singleton = 1").fetchone()
        previous_hash = state["last_hash"] if state else None
        created_at = datetime.now(timezone.utc).isoformat()
        record = {
            "integrity_record_id": f"integrity-{uuid4().hex}", "artifact_type": artifact_type,
            "artifact_id": artifact_id, "content_hash": content_hash, "previous_hash": previous_hash,
            "created_at": created_at, "actor_id": actor_id, "algorithm": ALGORITHM,
            "schema_version": SCHEMA_VERSION,
            "canonical_payload": canonical_payload,
        }
        record["record_hash"] = ledger_hash(record)
        connection.execute(
            """INSERT INTO integrity_records
            (integrity_record_id, artifact_type, artifact_id, content_hash, previous_hash, record_hash,
             canonical_payload, created_at, actor_id, algorithm, schema_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (record["integrity_record_id"], artifact_type, artifact_id, content_hash, previous_hash,
             record["record_hash"], canonical_payload, created_at, actor_id, ALGORITHM, SCHEMA_VERSION),
        )
        next_count = int(state["record_count"]) + 1 if state else 1
        connection.execute("UPDATE integrity_ledger_state SET record_count = ?, last_hash = ?, updated_at = ? WHERE singleton = 1", (next_count, record["record_hash"], created_at))
        if owns_connection:
            connection.commit()
        return record | {"verification_status": "NOT_VERIFIED"}
    except Exception:
        if owns_connection:
            connection.rollback()
        raise
    finally:
        if owns_connection:
            connection.close()


def _integrity_record(row: sqlite3.Row, *, include_canonical_payload: bool = False) -> dict[str, Any]:
    # Canonical snapshots are retained for forensic audit only. They may include
    # evidence excerpts, so integrity APIs expose hashes/status rather than payload.
    record = {key: row[key] for key in row.keys() if include_canonical_payload or key != "canonical_payload"}
    return record | {"verification_status": "NOT_VERIFIED"}


def _canonical_payload_is_valid(record: dict[str, Any]) -> bool:
    """Verify the stored canonical snapshot rather than trusting its hash."""
    try:
        envelope = json.loads(record["canonical_payload"])
        if not isinstance(envelope, dict) or envelope.get("artifact_type") != record["artifact_type"] or envelope.get("artifact_id") != record["artifact_id"]:
            return False
        expected_hash, expected_canonical = artifact_hash(record["artifact_type"], record["artifact_id"], envelope.get("payload"), schema_version=envelope.get("schema_version"))
        return expected_canonical == record["canonical_payload"] and expected_hash == record["content_hash"]
    except (TypeError, ValueError, json.JSONDecodeError):
        return False


def _live_integrity_payload(artifact_type: str, artifact_id: str, connection: sqlite3.Connection) -> dict[str, Any] | None:
    if artifact_type == "CONFIGURATION":
        row = connection.execute("SELECT record_json, content_sha256 FROM configurations WHERE configuration_id = ?", (artifact_id,)).fetchone()
        return {"configuration": json.loads(row["record_json"]), "content_sha256": row["content_sha256"]} if row else None
    if artifact_type == "ANALYSIS":
        row = connection.execute("SELECT response_json, security_ir_json FROM analysis_results WHERE analysis_id = ?", (artifact_id,)).fetchone()
        if not row:
            return None
        response = json.loads(row["response_json"])
        return {"analysis": response, "configuration_fingerprint": (response.get("configuration") or {}).get("content_sha256"), "security_ir": json.loads(row["security_ir_json"]) if row["security_ir_json"] else None}
    if artifact_type == "EVIDENCE":
        analysis_id, _, index_text = artifact_id.rpartition(":evidence:")
        row = connection.execute("SELECT response_json FROM analysis_results WHERE analysis_id = ?", (analysis_id,)).fetchone()
        if not row or not index_text.isdigit():
            return None
        evidence = json.loads(row["response_json"]).get("evidence", [])
        index = int(index_text)
        return {"analysis_id": analysis_id, "evidence": evidence[index]} if 0 <= index < len(evidence) else None
    if artifact_type == "MAPPING_VERSION":
        mapping_id, _, version_text = artifact_id.rpartition(":v")
        row = connection.execute("SELECT * FROM mapping_versions WHERE mapping_id = ? AND version = ?", (mapping_id, version_text)).fetchone()
        return _mapping_version_from_row(row) if row else None
    if artifact_type == "AI_PROPOSAL":
        row = connection.execute("SELECT record_json FROM interpretation_proposals WHERE proposal_id = ?", (artifact_id,)).fetchone()
        return json.loads(row["record_json"]) if row else None
    if artifact_type == "REMEDIATION_SIMULATION":
        row = connection.execute("SELECT response_json FROM simulation_results WHERE simulation_id = ?", (artifact_id,)).fetchone()
        return json.loads(row["response_json"]) if row else None
    # Reports are generated downloads, not persisted raw documents. Their immutable
    # report metadata snapshot remains verifiable through the ledger itself.
    return None


def verify_integrity_record(artifact_type: str, artifact_id: str, database_path: Path = DATABASE_PATH) -> dict[str, Any]:
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        row = connection.execute("SELECT * FROM integrity_records WHERE artifact_type = ? AND artifact_id = ? ORDER BY sequence DESC LIMIT 1", (artifact_type, artifact_id)).fetchone()
        if not row:
            return {"status": "NOT_FOUND", "artifact_type": artifact_type, "artifact_id": artifact_id}
        record = _integrity_record(row, include_canonical_payload=True)
        public_record = _integrity_record(row)
        if not _canonical_payload_is_valid(record):
            return public_record | {"status": "INVALID", "reason": "Canonical artifact snapshot does not match its stored content hash."}
        if ledger_hash(record) != record["record_hash"]:
            return public_record | {"status": "INVALID", "reason": "Ledger record hash does not match its immutable fields."}
        payload = _live_integrity_payload(artifact_type, artifact_id, connection)
        if payload is None and artifact_type != "REPORT":
            return public_record | {"status": "NOT_FOUND", "reason": "The stored audit artifact is unavailable."}
        if payload is not None:
            envelope = json.loads(record["canonical_payload"])
            current_hash, _ = artifact_hash(artifact_type, artifact_id, payload, schema_version=envelope.get("schema_version"))
            if current_hash != record["content_hash"]:
                return public_record | {"status": "INVALID", "reason": "Stored artifact content no longer matches its integrity record."}
        return public_record | {"status": "VALID", "verified_at": datetime.now(timezone.utc).isoformat()}
    finally:
        connection.close()


def get_integrity_records(artifact_type: str | None = None, artifact_id: str | None = None, database_path: Path = DATABASE_PATH) -> list[dict[str, Any]]:
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        clauses, args = [], []
        if artifact_type: clauses.append("artifact_type = ?"); args.append(artifact_type)
        if artifact_id: clauses.append("artifact_id = ?"); args.append(artifact_id)
        query = "SELECT * FROM integrity_records" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY sequence DESC"
        return [_integrity_record(row) for row in connection.execute(query, args).fetchall()]
    finally:
        connection.close()


def get_latest_integrity_record(artifact_type: str, artifact_id: str, database_path: Path = DATABASE_PATH) -> dict[str, Any] | None:
    records = get_integrity_records(artifact_type, artifact_id, database_path)
    return records[0] if records else None


def save_report_metadata(*, report_id: str, analysis_id: str, generated_by: str | None, integrity_record_id: str | None, metadata: dict[str, Any], database_path: Path = DATABASE_PATH) -> dict[str, Any]:
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        version = int(connection.execute("SELECT COALESCE(MAX(report_version), 0) AS version FROM reports WHERE analysis_id = ?", (analysis_id,)).fetchone()["version"]) + 1
        generated_at = datetime.now(timezone.utc).isoformat()
        connection.execute("INSERT INTO reports VALUES (?, ?, ?, ?, ?, ?, ?)", (report_id, analysis_id, version, generated_at, generated_by, integrity_record_id, json.dumps(metadata, sort_keys=True)))
        connection.commit()
        return {"report_id": report_id, "analysis_id": analysis_id, "report_version": version, "generated_at": generated_at, "generated_by": generated_by, "integrity_record_id": integrity_record_id, "metadata": metadata}
    except Exception:
        connection.rollback(); raise
    finally:
        connection.close()


def list_report_metadata(analysis_id: str, database_path: Path = DATABASE_PATH) -> list[dict[str, Any]]:
    initialize_database(database_path); connection = get_connection(database_path)
    try:
        return [{"report_id": row["report_id"], "analysis_id": row["analysis_id"], "report_version": row["report_version"], "generated_at": row["generated_at"], "generated_by": row["generated_by"], "integrity_record_id": row["integrity_record_id"], "metadata": json.loads(row["metadata_json"])} for row in connection.execute("SELECT * FROM reports WHERE analysis_id = ? ORDER BY report_version DESC", (analysis_id,)).fetchall()]
    finally: connection.close()


def verify_integrity_chain(database_path: Path = DATABASE_PATH) -> dict[str, Any]:
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        rows = connection.execute("SELECT * FROM integrity_records ORDER BY sequence ASC").fetchall()
        state = connection.execute("SELECT record_count, last_hash FROM integrity_ledger_state WHERE singleton = 1").fetchone()
        previous_hash = None
        for row in rows:
            record = _integrity_record(row, include_canonical_payload=True)
            if not _canonical_payload_is_valid(record) or record["previous_hash"] != previous_hash or ledger_hash(record) != record["record_hash"]:
                return {"status": "INVALID", "record_count": len(rows), "failed_record_id": record["integrity_record_id"], "reason": "The audit hash chain is broken."}
            previous_hash = record["record_hash"]
        if not state or state["record_count"] != len(rows) or state["last_hash"] != previous_hash:
            return {"status": "INVALID", "record_count": len(rows), "reason": "Ledger state does not match the append-only record sequence."}
        return {"status": "VALID", "record_count": len(rows), "last_hash": previous_hash, "verified_at": datetime.now(timezone.utc).isoformat()}
    finally:
        connection.close()


def create_batch(batch: BatchAnalysis, items: list[BatchItem], database_path: Path = DATABASE_PATH) -> None:
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO batches VALUES (?, ?)", (batch.batch_id, batch.model_dump_json()))
        connection.executemany("INSERT INTO batch_items VALUES (?, ?, ?)", [(item.batch_item_id, batch.batch_id, item.model_dump_json()) for item in items])
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def update_batch(batch: BatchAnalysis, database_path: Path = DATABASE_PATH) -> None:
    connection = get_connection(database_path)
    try:
        connection.execute("UPDATE batches SET record_json = ? WHERE batch_id = ?", (batch.model_dump_json(), batch.batch_id))
        connection.commit()
    finally:
        connection.close()


def update_batch_item(item: BatchItem, batch_id: str, database_path: Path = DATABASE_PATH) -> None:
    connection = get_connection(database_path)
    try:
        connection.execute("UPDATE batch_items SET record_json = ? WHERE batch_item_id = ? AND batch_id = ?", (item.model_dump_json(), item.batch_item_id, batch_id))
        connection.commit()
    finally:
        connection.close()


def save_interpretation_proposal(proposal: AIProposal, database_path: Path = DATABASE_PATH) -> None:
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        connection.execute("INSERT INTO interpretation_proposals (proposal_id, analysis_id, pattern_id, record_json) VALUES (?, ?, ?, ?)", (proposal.proposal_id, proposal.analysis_id, proposal.pattern_id, proposal.model_dump_json()))
        connection.execute("INSERT INTO interpretation_events (proposal_id, record_json) VALUES (?, ?)", (proposal.proposal_id, InterpretationEvent(proposal_id=proposal.proposal_id, action="PROPOSED", created_at=proposal.created_at).model_dump_json()))
        append_integrity_record("AI_PROPOSAL", proposal.proposal_id, proposal.model_dump(mode="json"), connection=connection)
        connection.commit()
    finally:
        connection.close()


def get_interpretation_proposals(analysis_id: str, database_path: Path = DATABASE_PATH) -> list[AIProposal]:
    connection = get_connection(database_path)
    try:
        rows = connection.execute("SELECT record_json FROM interpretation_proposals WHERE analysis_id = ? ORDER BY rowid", (analysis_id,)).fetchall()
        return [AIProposal.model_validate_json(row["record_json"]) for row in rows]
    finally:
        connection.close()


def get_all_interpretation_proposals(status: str | None = None, database_path: Path = DATABASE_PATH) -> list[AIProposal]:
    connection = get_connection(database_path)
    try:
        rows = connection.execute("SELECT record_json FROM interpretation_proposals ORDER BY rowid DESC").fetchall()
        proposals = [AIProposal.model_validate_json(row["record_json"]) for row in rows]
        if status:
            return [p for p in proposals if p.status == status]
        return proposals
    finally:
        connection.close()


def get_interpretation_proposal(proposal_id: str, database_path: Path = DATABASE_PATH) -> AIProposal | None:
    connection = get_connection(database_path)
    try:
        row = connection.execute("SELECT record_json FROM interpretation_proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
        return AIProposal.model_validate_json(row["record_json"]) if row else None
    finally:
        connection.close()


def get_interpretation_events(proposal_id: str, database_path: Path = DATABASE_PATH) -> list[InterpretationEvent]:
    connection = get_connection(database_path)
    try:
        rows = connection.execute("SELECT record_json FROM interpretation_events WHERE proposal_id = ? ORDER BY event_id", (proposal_id,)).fetchall()
        return [InterpretationEvent.model_validate_json(row["record_json"]) for row in rows]
    finally:
        connection.close()


def update_interpretation_proposal(proposal: AIProposal, event: InterpretationEvent, database_path: Path = DATABASE_PATH) -> None:
    connection = get_connection(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("UPDATE interpretation_proposals SET record_json = ? WHERE proposal_id = ?", (proposal.model_dump_json(), proposal.proposal_id))
        connection.execute("INSERT INTO interpretation_events (proposal_id, record_json) VALUES (?, ?)", (proposal.proposal_id, event.model_dump_json()))
        append_integrity_record("AI_PROPOSAL", proposal.proposal_id, proposal.model_dump(mode="json"), actor_id=event.reviewer_id, connection=connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_batch(batch_id: str, database_path: Path = DATABASE_PATH) -> BatchAnalysis | None:
    connection = get_connection(database_path)
    try:
        row = connection.execute("SELECT record_json FROM batches WHERE batch_id = ?", (batch_id,)).fetchone()
        return BatchAnalysis.model_validate_json(row["record_json"]) if row else None
    finally:
        connection.close()


def get_batch_items(batch_id: str, database_path: Path = DATABASE_PATH) -> list[BatchItem] | None:
    connection = get_connection(database_path)
    try:
        if connection.execute("SELECT 1 FROM batches WHERE batch_id = ?", (batch_id,)).fetchone() is None:
            return None
        rows = connection.execute("SELECT record_json FROM batch_items WHERE batch_id = ? ORDER BY rowid", (batch_id,)).fetchall()
        return [BatchItem.model_validate_json(row["record_json"]) for row in rows]
    finally:
        connection.close()


def connection_scope(database_path: Path = DATABASE_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Provide a small future-friendly connection scope."""

    connection = get_connection(database_path)
    try:
        yield connection
    finally:
        connection.close()


def save_analysis_result(
    *,
    analysis_id: str,
    filename: str,
    vendor: str,
    response: dict,
    security_ir: dict | None = None,
    device_record: Device | None = None,
    configuration_record: Configuration | None = None,
    actor_id: str | None = None,
    database_path: Path = DATABASE_PATH,
) -> None:
    """Persist a structured response and IR snapshot; raw uploaded text is not stored."""

    from datetime import datetime, timezone

    connection = get_connection(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if (device_record is None) != (configuration_record is None):
            raise ValueError("New inventory requires both device and configuration records.")
        if device_record is not None and configuration_record is not None:
            if configuration_record.device_id != device_record.device_id or configuration_record.detected_vendor != vendor or device_record.vendor != vendor:
                raise ValueError("Device/configuration association does not match the analysis.")
            duplicate = connection.execute("SELECT configuration_id FROM configurations WHERE content_sha256 = ? ORDER BY rowid LIMIT 1", (configuration_record.content_sha256,)).fetchone()
            configuration_record.duplicate_of_configuration_id = duplicate["configuration_id"] if duplicate else None
            response["configuration"] = configuration_record.model_dump(mode="json")
            connection.execute("INSERT INTO devices VALUES (?, ?) ON CONFLICT(device_id) DO UPDATE SET record_json=excluded.record_json", (device_record.device_id, device_record.model_dump_json()))
            connection.execute("INSERT INTO configurations VALUES (?, ?, ?, ?)", (configuration_record.configuration_id, device_record.device_id, configuration_record.content_sha256, configuration_record.model_dump_json()))
            append_integrity_record("CONFIGURATION", configuration_record.configuration_id, {"configuration": configuration_record.model_dump(mode="json"), "content_sha256": configuration_record.content_sha256}, actor_id=actor_id, connection=connection)
        configuration = response.get("configuration")
        if configuration:
            stored = connection.execute("SELECT record_json FROM configurations WHERE configuration_id = ?", (configuration["configuration_id"],)).fetchone()
            if stored is None or json.loads(stored["record_json"]) != configuration:
                raise ValueError("Analysis configuration must match a stored configuration snapshot.")
        connection.execute(
            """
            INSERT INTO analysis_results
                (analysis_id, filename, vendor, response_json, security_ir_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                filename,
                vendor,
                json.dumps(response, sort_keys=True),
                json.dumps(security_ir, sort_keys=True) if security_ir is not None else None,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        if configuration:
            connection.execute("INSERT INTO analysis_configurations VALUES (?, ?)", (analysis_id, configuration["configuration_id"]))
        analysis_payload = {
            "analysis": response,
            "configuration_fingerprint": (response.get("configuration") or {}).get("content_sha256"),
            "security_ir": security_ir,
        }
        append_integrity_record("ANALYSIS", analysis_id, analysis_payload, actor_id=actor_id, connection=connection)
        for index, evidence in enumerate(response.get("evidence", [])):
            append_integrity_record("EVIDENCE", f"{analysis_id}:evidence:{index}", {"analysis_id": analysis_id, "evidence": evidence}, actor_id=actor_id, connection=connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_device(device_id: str, database_path: Path = DATABASE_PATH) -> Device | None:
    connection = get_connection(database_path)
    try:
        row = connection.execute("SELECT record_json FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        return Device.model_validate_json(row["record_json"]) if row else None
    finally:
        connection.close()


def get_configuration_history(configuration_id: str, database_path: Path = DATABASE_PATH) -> ConfigurationHistory | None:
    connection = get_connection(database_path)
    try:
        row = connection.execute("SELECT record_json FROM configurations WHERE configuration_id = ?", (configuration_id,)).fetchone()
        if not row:
            return None
        analyses = connection.execute("SELECT a.analysis_id FROM analysis_results a JOIN analysis_configurations c ON c.analysis_id = a.analysis_id WHERE c.configuration_id = ? ORDER BY a.created_at, a.analysis_id", (configuration_id,)).fetchall()
        return ConfigurationHistory(configuration=Configuration.model_validate_json(row["record_json"]), analysis_ids=[a["analysis_id"] for a in analyses])
    finally:
        connection.close()


def get_device_analysis_history(device_id: str, database_path: Path = DATABASE_PATH) -> DeviceAnalysisHistory | None:
    connection = get_connection(database_path)
    try:
        if connection.execute("SELECT 1 FROM devices WHERE device_id = ?", (device_id,)).fetchone() is None:
            return None
        rows = connection.execute("""
            SELECT a.analysis_id FROM analysis_results a
            JOIN analysis_configurations ac ON ac.analysis_id = a.analysis_id
            JOIN configurations c ON c.configuration_id = ac.configuration_id
            WHERE c.device_id = ? ORDER BY a.created_at, a.analysis_id
        """, (device_id,)).fetchall()
        return DeviceAnalysisHistory(device_id=device_id, analysis_ids=[row["analysis_id"] for row in rows])
    finally:
        connection.close()


def get_analysis_result(
    analysis_id: str,
    database_path: Path = DATABASE_PATH,
) -> dict | None:
    """Read one persisted analysis response for local-demo verification."""

    connection = get_connection(database_path)
    try:
        row = connection.execute(
            "SELECT response_json FROM analysis_results WHERE analysis_id = ?",
            (analysis_id,),
        ).fetchone()
        return json.loads(row["response_json"]) if row else None
    finally:
        connection.close()


def get_analysis_bundle(
    analysis_id: str,
    database_path: Path = DATABASE_PATH,
) -> dict[str, Any] | None:
    """Load an immutable analysis response and its stored Security IR snapshot."""

    connection = get_connection(database_path)
    try:
        row = connection.execute(
            "SELECT response_json, security_ir_json FROM analysis_results WHERE analysis_id = ?",
            (analysis_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "response": json.loads(row["response_json"]),
            "security_ir": json.loads(row["security_ir_json"]) if row["security_ir_json"] else None,
        }
    finally:
        connection.close()


def console_analyses(*, vendor: str | None = None, device_id: str | None = None, status: str | None = None, query: str | None = None, offset: int = 0, limit: int = 50, database_path: Path = DATABASE_PATH) -> tuple[list[dict[str, Any]], int]:
    """Read stored snapshots for the console; never recalculate a result."""
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        # Keep filtering/counting/paging in SQLite. JSON is persisted audit data,
        # so only the requested page is deserialized in Python.
        clauses, args = [], []
        if vendor is not None:
            clauses.append("vendor = ?"); args.append(vendor)
        if device_id is not None:
            clauses.append("device_id = ?"); args.append(device_id)
        if status is not None:
            clauses.append("overall_status = ?"); args.append(status)
        if query is not None:
            clauses.append("LOWER(analysis_id || ' ' || COALESCE(filename, '') || ' ' || COALESCE(configuration_id, '') || ' ' || COALESCE(device_id, '') || ' ' || COALESCE(hostname, '')) LIKE ?")
            args.append(f"%{query.lower()}%")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        base = """
            SELECT analysis_id, response_json, created_at,
                   json_extract(response_json, '$.vendor') AS vendor,
                   json_extract(response_json, '$.filename') AS filename,
                   json_extract(response_json, '$.configuration.configuration_id') AS configuration_id,
                   json_extract(response_json, '$.configuration.device_id') AS device_id,
                   json_extract(response_json, '$.device.hostname') AS hostname,
                   CASE
                     WHEN EXISTS (SELECT 1 FROM json_each(response_json, '$.results') r WHERE json_extract(r.value, '$.diagnostic_of') IS NULL AND json_extract(r.value, '$.result') = 'FAIL') THEN 'FAIL'
                     WHEN EXISTS (SELECT 1 FROM json_each(response_json, '$.results') r WHERE json_extract(r.value, '$.diagnostic_of') IS NULL AND json_extract(r.value, '$.result') = 'UNKNOWN') THEN 'UNKNOWN'
                     ELSE 'PASS' END AS overall_status
            FROM analysis_results
        """
        count = int(connection.execute(f"SELECT COUNT(*) AS count FROM ({base}){where}", args).fetchone()["count"])
        rows = connection.execute(f"SELECT * FROM ({base}){where} ORDER BY created_at DESC, analysis_id DESC LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
        records = []
        for row in rows:
            response = json.loads(row["response_json"])
            config = response.get("configuration") or {}
            root = [item for item in response.get("results", []) if not item.get("diagnostic_of")]
            counts = {state: sum(item.get("result") == state for item in root) for state in ("PASS", "FAIL", "UNKNOWN")}
            overall = "FAIL" if counts["FAIL"] else "UNKNOWN" if counts["UNKNOWN"] else "PASS"
            record = {"analysis_id": row["analysis_id"], "created_at": row["created_at"], "filename": response.get("filename"), "vendor": response.get("vendor"), "device": response.get("device", {}), "configuration": config, "results": root, "evidence": response.get("evidence", []), "pass_findings": counts["PASS"], "fail_findings": counts["FAIL"], "unknown_findings": counts["UNKNOWN"], "overall_status": overall, "parent_analysis_id": response.get("parent_analysis_id"), "reanalyzed": response.get("reanalyzed", False), "mapping_version": response.get("mapping_version"), "report_available": True, "unknown_patterns": response.get("unknown_patterns", [])}
            records.append(record)
        return records, count
    finally:
        connection.close()


def console_devices(*, query: str | None = None, offset: int = 0, limit: int = 50, database_path: Path = DATABASE_PATH) -> tuple[list[dict[str, Any]], int]:
    initialize_database(database_path); connection = get_connection(database_path)
    try:
        where, args = "", []
        if query is not None:
            where = " WHERE LOWER(device_id || ' ' || COALESCE(json_extract(record_json, '$.hostname'), '') || ' ' || COALESCE(json_extract(record_json, '$.vendor'), '')) LIKE ?"; args = [f"%{query.lower()}%"]
        total = int(connection.execute(f"SELECT COUNT(*) AS count FROM devices{where}", args).fetchone()["count"])
        rows = connection.execute(f"SELECT device_id, record_json FROM devices{where} ORDER BY device_id LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall(); records=[]
        for row in rows:
            device=json.loads(row["record_json"]); did=row["device_id"]
            configs=connection.execute("SELECT COUNT(*) count FROM configurations WHERE device_id=?", (did,)).fetchone()["count"]
            analyses=connection.execute("SELECT COUNT(*) count FROM analysis_configurations ac JOIN configurations c ON c.configuration_id=ac.configuration_id WHERE c.device_id=?", (did,)).fetchone()["count"]
            latest=connection.execute("SELECT a.analysis_id FROM analysis_results a JOIN analysis_configurations ac ON ac.analysis_id=a.analysis_id JOIN configurations c ON c.configuration_id=ac.configuration_id WHERE c.device_id=? ORDER BY a.created_at DESC LIMIT 1", (did,)).fetchone()
            record={**device, "configuration_count": configs, "analysis_count": analyses, "latest_analysis_id": latest["analysis_id"] if latest else None}
            records.append(record)
        return records, total
    finally: connection.close()


def console_configurations(*, query: str | None = None, offset: int = 0, limit: int = 50, database_path: Path = DATABASE_PATH) -> tuple[list[dict[str, Any]], int]:
    initialize_database(database_path); connection=get_connection(database_path)
    try:
        where, args = "", []
        if query is not None:
            where = " WHERE LOWER(configuration_id || ' ' || COALESCE(json_extract(record_json, '$.device_id'), '') || ' ' || COALESCE(json_extract(record_json, '$.source_filename'), '')) LIKE ?"; args = [f"%{query.lower()}%"]
        total = int(connection.execute(f"SELECT COUNT(*) AS count FROM configurations{where}", args).fetchone()["count"])
        rows=connection.execute(f"SELECT configuration_id, record_json FROM configurations{where} ORDER BY rowid DESC LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall(); records=[]
        for row in rows:
            item=json.loads(row["record_json"]); item["analysis_count"]=connection.execute("SELECT COUNT(*) count FROM analysis_configurations WHERE configuration_id=?",(row["configuration_id"],)).fetchone()["count"]
            records.append(item)
        return records,total
    finally: connection.close()


def console_batches(*, offset: int = 0, limit: int = 50, database_path: Path = DATABASE_PATH) -> tuple[list[dict[str, Any]], int]:
    initialize_database(database_path); connection=get_connection(database_path)
    try:
        total = int(connection.execute("SELECT COUNT(*) AS count FROM batches").fetchone()["count"])
        rows=connection.execute("SELECT record_json FROM batches ORDER BY rowid DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall(); return [json.loads(row["record_json"]) for row in rows],total
    finally: connection.close()


def save_simulation_result(
    *,
    simulation_id: str,
    parent_analysis_id: str,
    remediation_id: str,
    response: dict,
    actor_id: str | None = None,
    database_path: Path = DATABASE_PATH,
) -> None:
    """Persist a simulation result separately from immutable analyses."""

    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        connection.execute(
            """
            INSERT INTO simulation_results
                (simulation_id, parent_analysis_id, remediation_id, response_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                simulation_id,
                parent_analysis_id,
                remediation_id,
                json.dumps(response, sort_keys=True),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        append_integrity_record("REMEDIATION_SIMULATION", simulation_id, response, actor_id=actor_id, connection=connection)
        connection.commit()
    finally:
        connection.close()


def get_simulation_result(
    simulation_id: str,
    database_path: Path = DATABASE_PATH,
) -> dict | None:
    """Load one immutable simulation result."""

    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        row = connection.execute(
            "SELECT response_json FROM simulation_results WHERE simulation_id = ?",
            (simulation_id,),
        ).fetchone()
        return json.loads(row["response_json"]) if row else None
    finally:
        connection.close()


def get_latest_simulation_for_analysis(
    parent_analysis_id: str,
    database_path: Path = DATABASE_PATH,
) -> dict | None:
    """Return the newest simulation for an analysis without changing it."""

    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        row = connection.execute(
            """
            SELECT response_json FROM simulation_results
            WHERE parent_analysis_id = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (parent_analysis_id,),
        ).fetchone()
        return json.loads(row["response_json"]) if row else None
    finally:
        connection.close()


def get_unknown_pattern_context(
    pattern_id: str,
    database_path: Path = DATABASE_PATH,
) -> dict[str, Any] | None:
    """Find a persisted unknown pattern and its vendor without storing raw config."""

    connection = get_connection(database_path)
    try:
        rows = connection.execute(
            "SELECT response_json, vendor FROM analysis_results ORDER BY created_at DESC"
        ).fetchall()
        from ..domain.mapping import pattern_signature, normalized_context
        from ..domain.security_ir import UnknownPattern
        found = None
        signature = None
        for row in rows:
            response = json.loads(row["response_json"])
            for pattern in response.get("unknown_patterns", []):
                if pattern.get("pattern_id") == pattern_id:
                    current = (row["vendor"], pattern_signature(row["vendor"], pattern["raw_pattern"]), normalized_context(UnknownPattern.model_validate(pattern)))
                    if signature is not None and signature != current:
                        raise ValueError("Pattern ID has conflicting vendor/signature/context occurrences.")
                    signature = current
                    if found is None:
                        found = {"vendor": row["vendor"], "pattern": pattern, "analysis_id": response["analysis_id"]}
        return found
    finally:
        connection.close()


def save_mapping_version(
    *,
    pattern_id: str,
    vendor: str,
    pattern_signature: str,
    proposed_mapping: dict[str, bool],
    approved_mapping: dict[str, bool] | None,
    status: str,
    reviewer_id: str,
    action: str,
    reason: str | None = None,
    identity: dict | None = None,
    proposal_id: str | None = None,
    database_path: Path = DATABASE_PATH,
) -> dict[str, Any]:
    """Store one immutable mapping decision and update its active lineage."""

    initialize_database(database_path)
    now = datetime.now(timezone.utc).isoformat()
    if identity is not None:
        from ..domain.mapping import MappingIdentity
        identity = MappingIdentity.model_validate(identity).model_dump(mode="json")
    connection = get_connection(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT mapping_id, vendor, pattern_signature FROM mappings WHERE pattern_id = ?",
            (pattern_id,),
        ).fetchone()
        if existing:
            if existing["vendor"] != vendor or existing["pattern_signature"] != pattern_signature:
                raise ValueError("Cannot change mapping identity within an existing lineage.")
            prior = connection.execute("SELECT identity_json FROM mapping_versions WHERE mapping_id = ? AND identity_json IS NOT NULL ORDER BY version DESC LIMIT 1", (existing["mapping_id"],)).fetchone()
            if prior and identity and json.loads(prior["identity_json"])["context"] != identity["context"]:
                raise ValueError("Cannot change approved context within an existing lineage.")
            mapping_id = existing["mapping_id"]
            latest = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM mapping_versions WHERE mapping_id = ?",
                (mapping_id,),
            ).fetchone()
            version = int(latest["version"]) + 1
            connection.execute(
                "UPDATE mappings SET vendor = ?, pattern_signature = ?, current_version = ?, active = ?, updated_at = ? WHERE mapping_id = ?",
                (vendor, pattern_signature, version, int(status == "APPROVED"), now, mapping_id),
            )
        else:
            mapping_id = f"mapping-{uuid4().hex[:12]}"
            version = 1
            connection.execute(
                "INSERT INTO mappings (mapping_id, pattern_id, vendor, pattern_signature, current_version, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (mapping_id, pattern_id, vendor, pattern_signature, version, int(status == "APPROVED"), now, now),
            )

        active = status == "APPROVED"
        connection.execute(
            """
            INSERT INTO mapping_versions
                (mapping_id, pattern_id, vendor, pattern_signature, version, status,
                 proposed_mapping_json, approved_mapping_json, reviewer_id, action,
                 created_at, updated_at, active, proposal_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mapping_id,
                pattern_id,
                vendor,
                pattern_signature,
                version,
                status,
                json.dumps(proposed_mapping, sort_keys=True),
                json.dumps(approved_mapping, sort_keys=True) if approved_mapping is not None else None,
                reviewer_id,
                action,
                now,
                now,
                int(active),
                proposal_id,
            ),
        )
        connection.execute(
            "INSERT INTO mapping_approvals (mapping_id, version, action, reviewer_id, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (mapping_id, version, action, reviewer_id, reason, now),
        )
        connection.execute("UPDATE mapping_versions SET identity_json = ? WHERE mapping_id = ? AND version = ?", (json.dumps(identity) if identity else None, mapping_id, version))
        mapping_payload = {
            "mapping_id": mapping_id, "pattern_id": pattern_id, "vendor": vendor,
            "pattern_signature": pattern_signature, "proposed_mapping": proposed_mapping,
            "approved_mapping": approved_mapping, "status": status, "version": version,
            "reviewer_id": reviewer_id, "action": action, "created_at": now, "updated_at": now,
            "active": active, "identity": identity, "proposal_id": proposal_id,
        }
        append_integrity_record("MAPPING_VERSION", f"{mapping_id}:v{version}", mapping_payload, actor_id=reviewer_id, connection=connection)
        connection.commit()
        return {
            "mapping_id": mapping_id,
            "pattern_id": pattern_id,
            "vendor": vendor,
            "pattern_signature": pattern_signature,
            "proposed_mapping": proposed_mapping,
            "approved_mapping": approved_mapping,
            "status": status,
            "version": version,
            "reviewer_id": reviewer_id,
            "action": action,
            "created_at": now,
            "updated_at": now,
            "active": active,
        "identity": identity,
            "proposal_id": proposal_id,
        }
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _mapping_version_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "mapping_id": row["mapping_id"],
        "pattern_id": row["pattern_id"],
        "vendor": row["vendor"],
        "pattern_signature": row["pattern_signature"],
        "proposed_mapping": json.loads(row["proposed_mapping_json"]),
        "approved_mapping": json.loads(row["approved_mapping_json"]) if row["approved_mapping_json"] else None,
        "status": row["status"],
        "version": row["version"],
        "reviewer_id": row["reviewer_id"],
        "action": row["action"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        # A historical version retains the active state it had when approved;
        # list projections use the aggregate's current pointer when available.
        "active": bool(row["current_active"]) if "current_active" in row.keys() else bool(row["active"]),
        "identity": json.loads(row["identity_json"]) if row["identity_json"] else None,
        "proposal_id": row["proposal_id"] if "proposal_id" in row.keys() else None,
    }


def _knowledge_from_row(row: sqlite3.Row) -> dict[str, Any]:
    """Project a mapping version as auditable reusable knowledge.

    Mapping IDs and version rows remain canonical; this projection introduces no
    second authority and intentionally does not expose configuration text.
    """
    mapping = _mapping_version_from_row(row)
    identity = mapping["identity"] or {}
    approved = mapping["approved_mapping"] or {}
    target_property = next(iter(sorted(approved)), None)
    if mapping["active"] and mapping["status"] == "APPROVED":
        knowledge_status = "ACTIVE"
    elif mapping["status"] == "APPROVED":
        knowledge_status = "APPROVED"
    elif mapping["status"] == "REJECTED":
        knowledge_status = "REVIEWED"
    else:
        knowledge_status = "DEACTIVATED"
    return {
        "knowledge_id": mapping["mapping_id"], "mapping_id": mapping["mapping_id"],
        "pattern_id": mapping["pattern_id"], "vendor": mapping["vendor"],
        "pattern_signature": mapping["pattern_signature"],
        "normalized_context": identity.get("context"), "target_property": target_property,
        "approved_value": approved.get(target_property) if target_property else None,
        "approved_mapping": approved or None, "source_pattern": identity.get("source_pattern"),
        "status": knowledge_status, "version": mapping["version"],
        "reviewer_id": mapping["reviewer_id"], "originating_proposal_id": mapping["proposal_id"],
        "approved_at": mapping["updated_at"] if mapping["status"] == "APPROVED" else None,
        "created_at": mapping["created_at"], "updated_at": mapping["updated_at"],
        "active": mapping["active"], "action": mapping["action"],
    }


def list_knowledge(*, vendor: str | None = None, property_name: str | None = None, status: str | None = None, database_path: Path = DATABASE_PATH) -> list[dict[str, Any]]:
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        rows = connection.execute("""
            SELECT v.*, CASE WHEN m.current_version = v.version AND m.active = 1 THEN 1 ELSE 0 END AS current_active
            FROM mapping_versions v JOIN mappings m ON m.mapping_id = v.mapping_id
            ORDER BY v.created_at DESC, v.version DESC
        """).fetchall()
        records = [_knowledge_from_row(row) for row in rows]
        return [record for record in records if (vendor is None or record["vendor"] == vendor) and (property_name is None or property_name in (record["approved_mapping"] or {})) and (status is None or record["status"] == status)]
    finally:
        connection.close()


def get_knowledge(knowledge_id: str, version: int | None = None, database_path: Path = DATABASE_PATH) -> dict[str, Any] | None:
    records = [item for item in list_knowledge(database_path=database_path) if item["knowledge_id"] == knowledge_id]
    if version is not None:
        records = [item for item in records if item["version"] == version]
    return records[0] if records else None


def knowledge_usage(mapping_id: str, version: int, database_path: Path = DATABASE_PATH) -> dict[str, Any]:
    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        # A deactivation creates a new version. Surface lineage usage on the
        # current knowledge entry without moving or rewriting historical usage.
        row = connection.execute("""SELECT COALESCE(SUM(referenced_count), 0) AS referenced_count,
            COALESCE(SUM(applied_count), 0) AS applied_count,
            MAX(last_referenced_at) AS last_referenced_at, MAX(last_applied_at) AS last_applied_at
            FROM knowledge_usage WHERE mapping_id = ?""", (mapping_id,)).fetchone()
        return dict(row) if row else {"referenced_count": 0, "applied_count": 0, "last_referenced_at": None, "last_applied_at": None}
    finally:
        connection.close()


def record_knowledge_usage(mapping_id: str, version: int, *, applied: bool = False, database_path: Path = DATABASE_PATH) -> None:
    """Record a reference/application without altering approval or compliance state."""
    initialize_database(database_path)
    now = datetime.now(timezone.utc).isoformat()
    connection = get_connection(database_path)
    try:
        connection.execute("INSERT INTO knowledge_usage (mapping_id, version, referenced_count, applied_count, last_referenced_at, last_applied_at) VALUES (?, ?, 1, ?, ?, ?) ON CONFLICT(mapping_id, version) DO UPDATE SET referenced_count = referenced_count + 1, applied_count = applied_count + excluded.applied_count, last_referenced_at = excluded.last_referenced_at, last_applied_at = CASE WHEN excluded.applied_count = 1 THEN excluded.last_applied_at ELSE knowledge_usage.last_applied_at END", (mapping_id, version, int(applied), now, now if applied else None))
        connection.commit()
    finally:
        connection.close()


def find_knowledge(vendor: str, signature: str, context: str, target_property: str | None = None, database_path: Path = DATABASE_PATH) -> dict[str, list[dict[str, Any]]]:
    """Classify exact, related and conflicting approved knowledge; no fuzzy match."""
    all_records = list_knowledge(vendor=vendor, database_path=database_path)
    matching = [item for item in all_records if item["pattern_signature"] == signature and item["normalized_context"] == context]
    active = [item for item in matching if item["active"]]
    values = {(key, value) for item in active for key, value in (item["approved_mapping"] or {}).items()}
    conflicts = active if len(values) > len({key for key, _ in values}) else []
    exact = [item for item in active if target_property is None or target_property in (item["approved_mapping"] or {})]
    related = [item for item in all_records if item not in matching and item["pattern_signature"] == signature]
    for item in exact + related + conflicts:
        record_knowledge_usage(item["mapping_id"], item["version"], database_path=database_path)
    return {"exact_matches": exact, "related_knowledge": related, "conflicts": conflicts}


def deactivate_knowledge(knowledge_id: str, reviewer_id: str, reason: str | None, database_path: Path = DATABASE_PATH) -> dict[str, Any] | None:
    """Deactivate current approved knowledge while retaining its complete history."""
    initialize_database(database_path)
    now = datetime.now(timezone.utc).isoformat()
    connection = get_connection(database_path)
    try:
        row = connection.execute("""
            SELECT v.* FROM mapping_versions v JOIN mappings m ON m.mapping_id = v.mapping_id
            WHERE v.mapping_id = ? AND m.current_version = v.version AND m.active = 1
            LIMIT 1
        """, (knowledge_id,)).fetchone()
        if not row:
            return None
        # Deactivation is a new immutable state, never a rewrite of the
        # approved historical version.
        next_version = int(row["version"]) + 1
        identity = json.loads(row["identity_json"]) if row["identity_json"] else None
        connection.execute("UPDATE mappings SET current_version = ?, active = 0, updated_at = ? WHERE mapping_id = ?", (next_version, now, knowledge_id))
        connection.execute("""INSERT INTO mapping_versions
            (mapping_id, pattern_id, vendor, pattern_signature, version, status, proposed_mapping_json, approved_mapping_json, reviewer_id, action, created_at, updated_at, active, proposal_id, identity_json)
            VALUES (?, ?, ?, ?, ?, 'INACTIVE', ?, ?, ?, 'DEACTIVATE', ?, ?, 0, ?, ?)""",
            (knowledge_id, row["pattern_id"], row["vendor"], row["pattern_signature"], next_version, row["proposed_mapping_json"], row["approved_mapping_json"], reviewer_id, now, now, row["proposal_id"], json.dumps(identity) if identity else None))
        connection.execute("INSERT INTO mapping_approvals (mapping_id, version, action, reviewer_id, reason, created_at) VALUES (?, ?, 'DEACTIVATE', ?, ?, ?)", (knowledge_id, next_version, reviewer_id, reason, now))
        changed = connection.execute("SELECT * FROM mapping_versions WHERE mapping_id = ? AND version = ?", (knowledge_id, next_version)).fetchone()
        changed_payload = _mapping_version_from_row(changed)
        append_integrity_record("MAPPING_VERSION", f"{knowledge_id}:v{next_version}", changed_payload, actor_id=reviewer_id, connection=connection)
        connection.commit()
        return _knowledge_from_row(changed)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_mapping_versions(
    pattern_id: str,
    database_path: Path = DATABASE_PATH,
) -> list[dict[str, Any]]:
    """Return all mapping versions, oldest first, without deleting lineage."""

    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        rows = connection.execute(
            """SELECT v.*, m.current_version, m.active AS lineage_active
            FROM mapping_versions v JOIN mappings m ON m.mapping_id = v.mapping_id
            WHERE v.pattern_id = ? ORDER BY v.version ASC""",
            (pattern_id,),
        ).fetchall()
        versions = []
        for row in rows:
            item = _mapping_version_from_row(row)
            # Supersession is derived from the immutable lineage pointer. It
            # remains visible as INACTIVE for API compatibility without
            # rewriting the historical approved snapshot used by integrity.
            if row["current_version"] != row["version"] and item["status"] == "APPROVED":
                item["status"] = "INACTIVE"
                item["active"] = False
            elif row["current_version"] == row["version"]:
                item["active"] = bool(row["lineage_active"])
            versions.append(item)
        return versions
    finally:
        connection.close()


def get_latest_mapping(
    pattern_id: str,
    database_path: Path = DATABASE_PATH,
) -> dict[str, Any] | None:
    """Return the newest stored version for one pattern, if any."""

    versions = get_mapping_versions(pattern_id, database_path)
    return versions[-1] if versions else None


def get_active_approved_mapping(
    pattern_id: str,
    database_path: Path = DATABASE_PATH,
) -> dict[str, Any] | None:
    """Return only the currently active approved mapping for a pattern."""

    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        row = connection.execute(
            """
            SELECT v.* FROM mapping_versions v JOIN mappings m ON m.mapping_id = v.mapping_id
            WHERE v.pattern_id = ? AND v.status = 'APPROVED' AND m.current_version = v.version AND m.active = 1
            ORDER BY v.version DESC LIMIT 1
            """,
            (pattern_id,),
        ).fetchone()
        return _mapping_version_from_row(row) if row else None
    finally:
        connection.close()


def find_approved_mapping_references(vendor: str, pattern_signature: str, context: str, database_path: Path = DATABASE_PATH) -> list[str]:
    """Return only exact identity matches; semantic similarity never authorizes reuse."""

    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        rows = connection.execute("SELECT mapping_id, version, identity_json FROM mapping_versions WHERE vendor = ? AND pattern_signature = ? AND status = 'APPROVED' ORDER BY updated_at DESC", (vendor, pattern_signature)).fetchall()
        references = []
        for row in rows:
            identity = json.loads(row["identity_json"]) if row["identity_json"] else None
            if identity and identity.get("context") == context:
                references.append(f"{row['mapping_id']}:v{row['version']}")
        return references
    finally:
        connection.close()
