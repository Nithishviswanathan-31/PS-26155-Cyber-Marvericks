import logging
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, status, Request

from ..config import load_demo_controls, CatalogueError
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.control_engine import DeterministicControlEngine
from ..domain.evidence import build_evidence
from ..domain.mapping import MappingVersion
from ..domain.schemas import AnalysisDeviceResponse, AnalysisResponse, ControlResultSummary
from ..domain.security_ir import SecurityIR
from ..services.mapping_application_service import MappingApplicationError, MappingApplicationService
from ..storage.database import (
    get_active_approved_mapping,
    get_analysis_bundle,
    get_latest_mapping,
    record_knowledge_usage,
    save_analysis_result,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analyze", tags=["analysis"])


@router.post("/{analysis_id}/reanalyze", response_model=AnalysisResponse)
def reanalyze_configuration(analysis_id: str, request: Request) -> AnalysisResponse:
    """Explicitly re-analyze an immutable original using active approved mappings."""

    bundle = get_analysis_bundle(analysis_id)
    if bundle is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, ApiErrorCode.ANALYSIS_NOT_FOUND, "The original analysis was not found.")

    try:
        original_response = AnalysisResponse.model_validate(bundle["response"])
    except (TypeError, ValueError) as exc:
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.REANALYSIS_FAILED, "The original analysis response is invalid.") from exc

    if original_response.reanalyzed:
        raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.REANALYSIS_FAILED, "Re-analysis must start from an original analysis, not a re-analysis result.")
    if original_response.vendor != "astranet":
        raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.REANALYSIS_FAILED, "This focused re-analysis workflow supports fictional AstraNet analyses only.")
    if not bundle["security_ir"]:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.REANALYSIS_FAILED, "The original analysis has no stored Security IR snapshot for re-analysis.")

    try:
        original_ir = SecurityIR.model_validate(bundle["security_ir"])
    except (TypeError, ValueError) as exc:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.REANALYSIS_FAILED, "The original Security IR snapshot is invalid and cannot be re-analyzed.") from exc

    if not original_ir.unknown_patterns:
        raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.UNKNOWN_PATTERN, "The original analysis has no unknown pattern to re-analyze.")

    mappings: list[MappingVersion] = []
    for pattern in original_ir.unknown_patterns:
        raw_mapping = get_active_approved_mapping(pattern.pattern_id)
        if raw_mapping is None:
            latest_mapping = get_latest_mapping(pattern.pattern_id)
            latest_status = str(latest_mapping.get("status", "")) if latest_mapping else ""
            if latest_status == "REJECTED":
                code = ApiErrorCode.REJECTED_MAPPING
            elif latest_status == "INACTIVE":
                code = ApiErrorCode.INACTIVE_MAPPING
            else:
                code = ApiErrorCode.NO_ACTIVE_MAPPING
            raise ApiError(
                status.HTTP_409_CONFLICT,
                code,
                f"No active approved mapping exists for unknown pattern '{pattern.pattern_id}'.",
            )
        try:
            mappings.append(MappingVersion.model_validate(raw_mapping))
        except (TypeError, ValueError) as exc:
            raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.INVALID_MAPPING, f"The active mapping for '{pattern.pattern_id}' is invalid.") from exc

    try:
        enriched_ir = original_ir
        application_service = MappingApplicationService()
        for mapping in mappings:
            enriched_ir = application_service.apply(
                enriched_ir,
                mapping,
                pattern_id=mapping.pattern_id,
            )
    except MappingApplicationError as exc:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.INVALID_MAPPING, f"The approved mapping could not be applied: {exc}") from exc

    try:
        controls = load_demo_controls()
        evaluations = DeterministicControlEngine().evaluate_all(
            enriched_ir,
            controls,
        )
        evidence = [
            item
            for evaluation in evaluations
            for item in build_evidence(enriched_ir, evaluation)
        ]
    except CatalogueError:
        raise
    except Exception as exc:
        logger.exception("Re-analysis evaluation failed for %s", analysis_id)
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.REANALYSIS_FAILED, "Re-analysis evaluation or evidence generation failed.") from exc

    child_analysis_id = str(uuid4())
    reanalyzed_at = datetime.now(timezone.utc)
    first_mapping = mappings[0]
    response = AnalysisResponse(
        analysis_id=child_analysis_id,
        filename=original_response.filename,
        configuration=original_response.configuration,
        vendor=enriched_ir.device.vendor,
        device=AnalysisDeviceResponse(
            hostname=enriched_ir.device.hostname,
            version=enriched_ir.device.version,
            device_model=enriched_ir.device.device_model,
            platform=enriched_ir.device.platform,
            serial_number=enriched_ir.device.serial_number,
            device_id=enriched_ir.device.device_id,
        ),
        results=[
            ControlResultSummary(
                control_id=evaluation.control_id,
                control_name=evaluation.control_name,
                diagnostic_of=next(c.diagnostic_of for c in controls if c.control_id == evaluation.control_id),
                result=evaluation.result,
                expected=evaluation.expected,
                actual=evaluation.actual,
                explanation=evaluation.explanation,
            )
            for evaluation in evaluations
        ],
        evidence=evidence,
        unknown_patterns=enriched_ir.unknown_patterns,
        recognized_patterns=enriched_ir.recognized_patterns,
        parent_analysis_id=analysis_id,
        reanalyzed=True,
        mapping_id=first_mapping.mapping_id,
        mapping_version=first_mapping.version,
        reanalyzed_at=reanalyzed_at,
        message=f"Re-analysis completed using approved mapping v{first_mapping.version}.",
    )

    try:
        save_analysis_result(
            analysis_id=child_analysis_id,
            filename=response.filename,
            vendor=response.vendor,
            response=response.model_dump(mode="json"),
            security_ir=enriched_ir.model_dump(mode="json"),
            actor_id=getattr(request.state, "actor", {}).get("user_id"),
        )
    except Exception as exc:
        logger.exception("Could not persist re-analysis %s", child_analysis_id)
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.STORAGE_FAILURE, "The re-analysis result could not be stored.") from exc

    # Audit-only metric: it is written after the immutable analysis snapshot
    # and is never consulted during deterministic evaluation.
    for mapping in mappings:
        record_knowledge_usage(mapping.mapping_id, mapping.version, applied=True)

    return response
