from fastapi import APIRouter, Query, status, Request
from ..services.auth_service import reviewer_identity
from pydantic import BaseModel, Field

from ..domain.api_errors import ApiError, ApiErrorCode
from ..storage.database import deactivate_knowledge, find_knowledge, get_knowledge, get_mapping_versions, knowledge_usage, list_knowledge

router = APIRouter(prefix="/api/knowledge", tags=["adaptive knowledge base"])


class DeactivateRequest(BaseModel):
    reviewer_id: str = Field(min_length=1)
    reason: str | None = None


@router.get("")
def list_entries(vendor: str | None = None, property: str | None = None, status_filter: str | None = Query(default=None, alias="status")):
    return list_knowledge(vendor=vendor, property_name=property, status=status_filter)


@router.get("/{knowledge_id}")
def read_entry(knowledge_id: str, version: int | None = None):
    entry = get_knowledge(knowledge_id, version)
    if entry is None:
        raise ApiError(404, ApiErrorCode.INVALID_MAPPING, "Knowledge entry was not found.")
    entry["usage"] = knowledge_usage(knowledge_id, entry["version"])
    entry["history"] = get_mapping_versions(entry["pattern_id"])
    return entry


@router.get("/{knowledge_id}/conflicts")
def entry_conflicts(knowledge_id: str, version: int | None = None):
    entry = get_knowledge(knowledge_id, version)
    if entry is None:
        raise ApiError(404, ApiErrorCode.INVALID_MAPPING, "Knowledge entry was not found.")
    return find_knowledge(entry["vendor"], entry["pattern_signature"], entry["normalized_context"] or "", entry["target_property"])


@router.post("/{knowledge_id}/deactivate")
def deactivate_entry(knowledge_id: str, request: DeactivateRequest, http_request: Request):
    entry = deactivate_knowledge(knowledge_id, reviewer_identity(http_request, request.reviewer_id.strip()), request.reason)
    if entry is None:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.INACTIVE_MAPPING, "Knowledge entry is not active.")
    return {"knowledge": entry, "compliance_impact": "UNCHANGED", "message": "Knowledge deactivated. Existing analyses remain immutable; explicit re-analysis is required for any later evaluation."}
