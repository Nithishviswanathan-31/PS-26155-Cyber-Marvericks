from fastapi import APIRouter, status

from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.interpretation import AIProposal, InterpretationGenerateRequest, InterpretationListResponse
from ..services.interpretation_service import InterpretationUnavailable, get_interpretation_provider
from ..storage.database import (
    get_analysis_bundle,
    get_interpretation_events,
    get_interpretation_proposal,
    get_interpretation_proposals,
    save_interpretation_proposal,
    find_approved_mapping_references,
)
from ..domain.security_ir import UnknownPattern
from ..domain.mapping import pattern_signature, normalized_context
from ..storage.database import find_knowledge

router = APIRouter(prefix="/api/interpretations", tags=["controlled interpretation"])


def _patterns_for_analysis(analysis_id: str) -> tuple[dict, list[UnknownPattern]]:
    bundle = get_analysis_bundle(analysis_id)
    if bundle is None:
        raise ApiError(404, ApiErrorCode.ANALYSIS_NOT_FOUND, "Analysis was not found.")
    response = bundle["response"]
    return response, [UnknownPattern.model_validate(item) for item in response.get("unknown_patterns", [])]


@router.get("/proposals/{proposal_id}", response_model=AIProposal)
def read_interpretation(proposal_id: str) -> AIProposal:
    proposal = get_interpretation_proposal(proposal_id)
    if proposal is None:
        raise ApiError(404, ApiErrorCode.UNKNOWN_PATTERN, "Interpretation proposal was not found.")
    return proposal


@router.get("/proposals/{proposal_id}/history")
def read_interpretation_history(proposal_id: str):
    if get_interpretation_proposal(proposal_id) is None:
        raise ApiError(404, ApiErrorCode.UNKNOWN_PATTERN, "Interpretation proposal was not found.")
    return {"proposal_id": proposal_id, "events": get_interpretation_events(proposal_id)}


@router.get("/{analysis_id}", response_model=InterpretationListResponse)
def list_interpretations(analysis_id: str) -> InterpretationListResponse:
    _patterns_for_analysis(analysis_id)
    return InterpretationListResponse(analysis_id=analysis_id, proposals=get_interpretation_proposals(analysis_id))


@router.post("/{analysis_id}", response_model=InterpretationListResponse)
def generate_interpretations(analysis_id: str, request: InterpretationGenerateRequest | None = None) -> InterpretationListResponse:
    response, patterns = _patterns_for_analysis(analysis_id)
    requested = request.pattern_id if request else None
    if requested:
        patterns = [pattern for pattern in patterns if pattern.pattern_id == requested]
        if not patterns:
            raise ApiError(404, ApiErrorCode.UNKNOWN_PATTERN, "Unknown pattern was not found in this analysis.")
    existing = {proposal.pattern_id for proposal in get_interpretation_proposals(analysis_id)}
    provider = get_interpretation_provider()
    for pattern in patterns:
        if pattern.pattern_id in existing:
            continue
        try:
            proposal = provider.interpret(pattern, vendor=response["vendor"], analysis_id=analysis_id)
        except InterpretationUnavailable:
            continue
        knowledge = find_knowledge(response["vendor"], pattern_signature(response["vendor"], pattern.raw_pattern), normalized_context(pattern))
        proposal = proposal.model_copy(update={"related_approved_mapping_ids": [f"{item['mapping_id']}:v{item['version']}" for item in knowledge["exact_matches"]]})
        save_interpretation_proposal(proposal)
    return InterpretationListResponse(analysis_id=analysis_id, proposals=get_interpretation_proposals(analysis_id))
