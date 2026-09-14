import sqlite3
from collections.abc import Generator
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..config import DATABASE_PATH


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
        "simulation_results",
        "mapping_approvals",
        "mapping_versions",
        "mappings",
        "analysis_results",
    )
    connection = get_connection(database_path)
    try:
        deleted: dict[str, int] = {}
        for table in tables:
            cursor = connection.execute(f"DELETE FROM {table}")
            deleted[table] = cursor.rowcount
        connection.commit()
        return deleted
    except Exception:
        connection.rollback()
        raise
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
    database_path: Path = DATABASE_PATH,
) -> None:
    """Persist a structured response and IR snapshot; raw uploaded text is not stored."""

    from datetime import datetime, timezone

    connection = get_connection(database_path)
    try:
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
        connection.commit()
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


def save_simulation_result(
    *,
    simulation_id: str,
    parent_analysis_id: str,
    remediation_id: str,
    response: dict,
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
        for row in rows:
            response = json.loads(row["response_json"])
            for pattern in response.get("unknown_patterns", []):
                if pattern.get("pattern_id") == pattern_id:
                    return {"vendor": row["vendor"], "pattern": pattern}
        return None
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
    database_path: Path = DATABASE_PATH,
) -> dict[str, Any]:
    """Store one immutable mapping decision and update its active lineage."""

    initialize_database(database_path)
    now = datetime.now(timezone.utc).isoformat()
    connection = get_connection(database_path)
    try:
        existing = connection.execute(
            "SELECT mapping_id FROM mappings WHERE pattern_id = ?",
            (pattern_id,),
        ).fetchone()
        if existing:
            mapping_id = existing["mapping_id"]
            latest = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM mapping_versions WHERE mapping_id = ?",
                (mapping_id,),
            ).fetchone()
            version = int(latest["version"]) + 1
            connection.execute(
                "UPDATE mapping_versions SET status = 'INACTIVE', active = 0, updated_at = ? WHERE mapping_id = ? AND active = 1",
                (now, mapping_id),
            )
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
                 created_at, updated_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
        connection.execute(
            "INSERT INTO mapping_approvals (mapping_id, version, action, reviewer_id, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (mapping_id, version, action, reviewer_id, reason, now),
        )
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
        "active": bool(row["active"]),
    }


def get_mapping_versions(
    pattern_id: str,
    database_path: Path = DATABASE_PATH,
) -> list[dict[str, Any]]:
    """Return all mapping versions, oldest first, without deleting lineage."""

    initialize_database(database_path)
    connection = get_connection(database_path)
    try:
        rows = connection.execute(
            "SELECT * FROM mapping_versions WHERE pattern_id = ? ORDER BY version ASC",
            (pattern_id,),
        ).fetchall()
        return [_mapping_version_from_row(row) for row in rows]
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
            SELECT * FROM mapping_versions
            WHERE pattern_id = ? AND status = 'APPROVED' AND active = 1
            ORDER BY version DESC LIMIT 1
            """,
            (pattern_id,),
        ).fetchone()
        return _mapping_version_from_row(row) if row else None
    finally:
        connection.close()
