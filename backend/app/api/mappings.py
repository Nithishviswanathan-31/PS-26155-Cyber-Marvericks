from fastapi import APIRouter, status, Request
from ..services.auth_service import reviewer_identity

from ..domain.mapping import (
    CandidateMappingSuggestion,
    MappingDecisionRequest,
    MappingDecisionResponse,
    MappingHistoryResponse,
    MappingReviewResponse,
    MappingStatus,
    RejectMappingRequest,
    pattern_signature,
    normalized_context,
)
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.security_ir import UnknownPattern
from ..services.ai_suggestion_service import SuggestionUnavailable, get_demo_suggestion_service
from ..services.interpretation_service import InterpretationUnavailable, get_interpretation_provider
from ..domain.interpretation import AIProposal, InterpretationEvent
from ..storage.database import (
    get_latest_mapping,
    get_mapping_versions,
    get_unknown_pattern_context,
    save_mapping_version as store_mapping_version,
    get_interpretation_proposal,
    update_interpretation_proposal,
    get_interpretation_proposals,
    save_interpretation_proposal,
    find_approved_mapping_references,
    find_knowledge,
)
from datetime import datetime, timezone


router = APIRouter(prefix="/api/mappings", tags=["mapping review"])


def save_mapping_version(**values):
    try:
        return store_mapping_version(**values)
    except ValueError as exc:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.INVALID_MAPPING, str(exc)) from exc


def _get_pattern_context(pattern_id: str) -> tuple[str, UnknownPattern, str]:
    try:
        context = get_unknown_pattern_context(pattern_id)
    except ValueError as exc:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.INVALID_MAPPING, str(exc)) from exc
    if context is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, ApiErrorCode.UNKNOWN_PATTERN, "Unknown pattern was not found in a persisted analysis.")
    try:
        return str(context["vendor"]), UnknownPattern.model_validate(context["pattern"]), str(context["analysis_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.INTERNAL_ERROR, "The stored unknown pattern could not be loaded safely.") from exc


@router.get("/unknown/{pattern_id}", response_model=MappingReviewResponse)
def get_unknown_mapping_review(pattern_id: str) -> MappingReviewResponse:
    vendor, pattern, _ = _get_pattern_context(pattern_id)
    latest = get_latest_mapping(pattern_id)
    review = MappingReviewResponse(
        pattern_id=pattern_id,
        vendor=vendor,
        pattern=pattern,
        latest_mapping=latest,
    )
    # Retrieval is informational. It never attaches/apply a mapping to this IR.
    return review


@router.get("/unknown/{pattern_id}/knowledge")
def get_unknown_pattern_knowledge(pattern_id: str):
    vendor, pattern, _ = _get_pattern_context(pattern_id)
    return find_knowledge(vendor, pattern_signature(vendor, pattern.raw_pattern), normalized_context(pattern))


@router.post("/{pattern_id}/suggest", response_model=CandidateMappingSuggestion)
def suggest_mapping(pattern_id: str) -> CandidateMappingSuggestion:
    vendor, pattern, analysis_id = _get_pattern_context(pattern_id)
    if pattern.pattern_id != pattern_id:
        raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.UNKNOWN_PATTERN, "Pattern identifier does not match the stored pattern.")
    try:
        candidate = get_demo_suggestion_service().suggest(pattern, vendor=vendor)
        existing = next((item for item in get_interpretation_proposals(analysis_id) if item.pattern_id == pattern_id), None)
        if existing is None:
            proposal = get_interpretation_provider().interpret(pattern, vendor=vendor, analysis_id=analysis_id)
            proposal = proposal.model_copy(update={"related_approved_mapping_ids": find_approved_mapping_references(vendor, proposal.pattern_signature, normalized_context(pattern))})
            save_interpretation_proposal(proposal)
        else:
            proposal = existing
        return candidate.model_copy(update={"proposal_id": proposal.proposal_id})
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
    proposal_id: str | None = None,
) -> MappingDecisionResponse:
    vendor, pattern, source_analysis_id = _get_pattern_context(pattern_id)
    proposal = get_interpretation_proposal(proposal_id) if proposal_id else None
    if proposal_id and (proposal is None or proposal.pattern_id != pattern_id or proposal.vendor != vendor or proposal.analysis_id != source_analysis_id):
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.INVALID_MAPPING, "Interpretation proposal identity does not match the mapping target.")
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
        identity={
            "context": normalized_context(pattern),
            "target_properties": sorted(approved_mapping or proposed_mapping),
            "source_pattern": pattern.raw_pattern,
            "source_location": pattern.location.model_dump(mode="json"),
            "source_analysis_id": source_analysis_id,
        } if approved_mapping else None,
        proposal_id=proposal_id,
    )
    if proposal:
        proposal = proposal.model_copy(update={"status": "APPROVED" if mapping_status is MappingStatus.APPROVED else "REJECTED", "updated_at": datetime.now(timezone.utc)})
        update_interpretation_proposal(proposal, InterpretationEvent(proposal_id=proposal_id, action=action, reviewer_id=reviewer_id, mapping=approved_mapping, reason=reason, created_at=proposal.updated_at))
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
def approve_mapping(pattern_id: str, request: MappingDecisionRequest, http_request: Request) -> MappingDecisionResponse:
    return _save_decision(
        pattern_id=pattern_id,
        reviewer_id=reviewer_identity(http_request, request.reviewer_id),
        proposed_mapping=dict(request.semantic_mapping),
        approved_mapping=dict(request.semantic_mapping),
        mapping_status=MappingStatus.APPROVED,
        action="APPROVE",
        proposal_id=request.proposal_id,
    )


@router.post("/{pattern_id}/correct", response_model=MappingDecisionResponse)
def correct_mapping(pattern_id: str, request: MappingDecisionRequest, http_request: Request) -> MappingDecisionResponse:
    return _save_decision(
        pattern_id=pattern_id,
        reviewer_id=reviewer_identity(http_request, request.reviewer_id),
        proposed_mapping=dict(request.semantic_mapping),
        approved_mapping=dict(request.semantic_mapping),
        mapping_status=MappingStatus.APPROVED,
        action="CORRECT_AND_APPROVE",
        proposal_id=request.proposal_id,
    )


@router.post("/{pattern_id}/reject", response_model=MappingDecisionResponse)
def reject_mapping(pattern_id: str, request: RejectMappingRequest, http_request: Request) -> MappingDecisionResponse:
    return _save_decision(
        pattern_id=pattern_id,
        reviewer_id=reviewer_identity(http_request, request.reviewer_id),
        proposed_mapping={},
        approved_mapping=None,
        mapping_status=MappingStatus.REJECTED,
        action="REJECT",
        reason=request.reason,
        proposal_id=request.proposal_id,
    )


@router.get("/{pattern_id}/versions", response_model=MappingHistoryResponse)
def get_mapping_history(pattern_id: str) -> MappingHistoryResponse:
    vendor, _, _ = _get_pattern_context(pattern_id)
    return MappingHistoryResponse(
        pattern_id=pattern_id,
        vendor=vendor,
        versions=get_mapping_versions(pattern_id),
    )
