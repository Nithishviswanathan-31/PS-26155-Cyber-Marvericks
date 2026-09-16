"""Deterministic canonicalization and hash-chain primitives for audit integrity."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any


ALGORITHM = "SHA-256"
SCHEMA_VERSION = "integrity-v2"
ARTIFACT_TYPES = frozenset({
    "CONFIGURATION", "ANALYSIS", "EVIDENCE", "MAPPING_VERSION",
    "AI_PROPOSAL", "REMEDIATION_SIMULATION", "REPORT",
})


def _normalise(value: Any) -> Any:
    """Return JSON-safe data with stable object ordering handled by ``canonical_json``."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _normalise(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        # Array order is meaningful evidence order and is deliberately retained.
        return [_normalise(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"Unsupported value in integrity payload: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Stable JSON: sorted keys, UTF-8 characters and no presentation whitespace."""
    return json.dumps(_normalise(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def artifact_hash(artifact_type: str, artifact_id: str, payload: Any, *, schema_version: str | None = None) -> tuple[str, str]:
    if artifact_type not in ARTIFACT_TYPES:
        raise ValueError("Unsupported integrity artifact type.")
    canonical = canonical_json({
        "algorithm": ALGORITHM,
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "payload": payload,
        "schema_version": schema_version or SCHEMA_VERSION,
    })
    return sha256_hex(canonical), canonical


def ledger_hash(record: dict[str, Any]) -> str:
    """Hash immutable ledger fields, including the retained canonical snapshot.

    ``integrity-v1`` records pre-date payload binding and remain readable. New
    records are ``integrity-v2`` and bind the exact canonical bytes-equivalent
    representation into the chain hash.
    """
    fields = {
        "algorithm": record["algorithm"],
        "artifact_id": record["artifact_id"],
        "artifact_type": record["artifact_type"],
        "content_hash": record["content_hash"],
        "created_at": record["created_at"],
        "integrity_record_id": record["integrity_record_id"],
        "previous_hash": record["previous_hash"],
        "schema_version": record["schema_version"],
        "actor_id": record.get("actor_id"),
    }
    if record.get("schema_version") == SCHEMA_VERSION:
        fields["canonical_payload"] = record.get("canonical_payload")
    return sha256_hex(canonical_json(fields))
