from fastapi import APIRouter, HTTPException

from ..domain.integrity import ARTIFACT_TYPES
from ..storage.database import get_integrity_records, verify_integrity_chain, verify_integrity_record


router = APIRouter(prefix="/api/integrity", tags=["evidence integrity"])


def _artifact_type(value: str) -> str:
    value = value.upper()
    if value not in ARTIFACT_TYPES:
        raise HTTPException(status_code=422, detail="Unsupported integrity artifact type.")
    return value


@router.get("/chain")
def verify_chain():
    """Explicit verification only; dashboard reads do not traverse the ledger."""
    return verify_integrity_chain()


@router.get("/records")
def records(artifact_type: str | None = None, artifact_id: str | None = None):
    return {"items": get_integrity_records(_artifact_type(artifact_type) if artifact_type else None, artifact_id)}


@router.get("/{artifact_type}/{artifact_id}")
def status(artifact_type: str, artifact_id: str):
    return verify_integrity_record(_artifact_type(artifact_type), artifact_id)


@router.post("/{artifact_type}/{artifact_id}/verify")
def verify(artifact_type: str, artifact_id: str):
    return verify_integrity_record(_artifact_type(artifact_type), artifact_id)
