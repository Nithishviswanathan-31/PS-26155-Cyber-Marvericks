from fastapi import APIRouter, status

from ..domain.mapping import (
    CandidateMappingSuggestion,
    MappingDecisionRequest,
    MappingDecisionResponse,
    MappingHistoryResponse,
    MappingReviewResponse,
    MappingStatus,
    RejectMappingRequest,
    pattern_signature,
)
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.security_ir import UnknownPattern
from ..services.ai_suggestion_service import SuggestionUnavailable, get_demo_suggestion_service
from ..storage.database import (
    get_latest_mapping,
    get_mapping_versions,
    get_unknown_pattern_context,
    save_mapping_version,
)


router = APIRouter(prefix="/api/mappings", tags=["mapping review"])


def _get_pattern_context(pattern_id: str) -> tuple[str, UnknownPattern]:
    context = get_unknown_pattern_context(pattern_id)
    if context is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, ApiErrorCode.UNKNOWN_PATTERN, "Unknown pattern was not found in a persisted analysis.")
    try:
        return str(context["vendor"]), UnknownPattern.model_validate(context["pattern"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.INTERNAL_ERROR, "The stored unknown pattern could not be loaded safely.") from exc


@router.get("/unknown/{pattern_id}", response_model=MappingReviewResponse)
def get_unknown_mapping_review(pattern_id: str) -> MappingReviewResponse:
    vendor, pattern = _get_pattern_context(pattern_id)
    latest = get_latest_mapping(pattern_id)
    return MappingReviewResponse(
        pattern_id=pattern_id,
        vendor=vendor,
        pattern=pattern,
        latest_mapping=latest,
    )


@router.post("/{pattern_id}/suggest", response_model=CandidateMappingSuggestion)
def suggest_mapping(pattern_id: str) -> CandidateMappingSuggestion:
    vendor, pattern = _get_pattern_context(pattern_id)
    if pattern.pattern_id != pattern_id:
        raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.UNKNOWN_PATTERN, "Pattern identifier does not match the stored pattern.")
    try:
        return get_demo_suggestion_service().suggest(pattern, vendor=vendor)
    except SuggestionUnavailable as exc:
        raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.INVALID_MAPPING, str(exc)) from exc


def _save_decision(
    *,
    pattern_id: str,
    reviewer_id: str,
    proposed_mapping: dict[str, bool],
    approved_mapping: dict[str, bool] | None,
    mapping_status: MappingStatus,
    action: str,
    reason: str | None = None,
) -> MappingDecisionResponse:
    vendor, pattern = _get_pattern_context(pattern_id)
    if mapping_status is MappingStatus.APPROVED:
        try:
            # Approval is available only for a pattern with a controlled
            # candidate; the submitted mapping may still be human-corrected.
            get_demo_suggestion_service().suggest(pattern, vendor=vendor)
        except SuggestionUnavailable as exc:
            raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.INVALID_MAPPING, str(exc)) from exc
    stored = save_mapping_version(
        pattern_id=pattern_id,
        vendor=vendor,
        pattern_signature=pattern_signature(vendor, pattern.raw_pattern),
        proposed_mapping=proposed_mapping,
        approved_mapping=approved_mapping,
        status=mapping_status.value,
        reviewer_id=reviewer_id,
        action=action,
        reason=reason,
    )
    return MappingDecisionResponse(
        pattern_id=pattern_id,
        mapping=stored,
        message=(
            "Mapping approved and stored as versioned knowledge. Compliance remains unchanged until a later re-analysis."
            if mapping_status is MappingStatus.APPROVED
            else "Mapping rejected and stored as inactive knowledge. The pattern remains UNKNOWN."
        ),
    )


@router.post("/{pattern_id}/approve", response_model=MappingDecisionResponse)
def approve_mapping(pattern_id: str, request: MappingDecisionRequest) -> MappingDecisionResponse:
    return _save_decision(
        pattern_id=pattern_id,
        reviewer_id=request.reviewer_id,
        proposed_mapping=dict(request.semantic_mapping),
        approved_mapping=dict(request.semantic_mapping),
        mapping_status=MappingStatus.APPROVED,
        action="APPROVE",
    )


@router.post("/{pattern_id}/correct", response_model=MappingDecisionResponse)
def correct_mapping(pattern_id: str, request: MappingDecisionRequest) -> MappingDecisionResponse:
    return _save_decision(
        pattern_id=pattern_id,
        reviewer_id=request.reviewer_id,
        proposed_mapping=dict(request.semantic_mapping),
        approved_mapping=dict(request.semantic_mapping),
        mapping_status=MappingStatus.APPROVED,
        action="CORRECT_AND_APPROVE",
    )


@router.post("/{pattern_id}/reject", response_model=MappingDecisionResponse)
def reject_mapping(pattern_id: str, request: RejectMappingRequest) -> MappingDecisionResponse:
    return _save_decision(
        pattern_id=pattern_id,
        reviewer_id=request.reviewer_id,
        proposed_mapping={},
        approved_mapping=None,
        mapping_status=MappingStatus.REJECTED,
        action="REJECT",
        reason=request.reason,
    )


@router.get("/{pattern_id}/versions", response_model=MappingHistoryResponse)
def get_mapping_history(pattern_id: str) -> MappingHistoryResponse:
    vendor, _ = _get_pattern_context(pattern_id)
    return MappingHistoryResponse(
        pattern_id=pattern_id,
        vendor=vendor,
        versions=get_mapping_versions(pattern_id),
    )
