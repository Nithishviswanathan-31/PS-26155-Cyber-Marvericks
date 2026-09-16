"""A blockchain-ready boundary for the offline tamper-evident ledger.

``LocalHashChainLedger`` is intentionally *not* represented as a blockchain.
A future network ledger may implement this small interface without changing
artifact canonicalization or application callers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class IntegrityLedger(ABC):
    @abstractmethod
    def append(self, artifact_type: str, artifact_id: str, payload: Any, actor_id: str | None = None) -> dict[str, Any]: ...

    @abstractmethod
    def verify_chain(self) -> dict[str, Any]: ...


class LocalHashChainLedger(IntegrityLedger):
    """SQLite-backed implementation; imports storage lazily to avoid cycles."""

    def append(self, artifact_type: str, artifact_id: str, payload: Any, actor_id: str | None = None) -> dict[str, Any]:
        from ..storage.database import append_integrity_record
        return append_integrity_record(artifact_type, artifact_id, payload, actor_id=actor_id)

    def verify_chain(self) -> dict[str, Any]:
        from ..storage.database import verify_integrity_chain
        return verify_integrity_chain()
