import logging
from uuid import uuid4

from fastapi import APIRouter, status, Request

from ..config import load_demo_controls, CatalogueError
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.control_engine import DeterministicControlEngine
from ..domain.evidence import build_evidence
from ..domain.remediation import (
    RemediationDefinition,
    RemediationResponse,
    SimulationRequest,
    SimulationResponse,
)
from ..domain.schemas import AnalysisResponse, ControlResultSummary
from ..domain.security_ir import SecurityIR
from ..services.remediation_service import (
    RemediationError,
    apply_simulation,
    get_remediation,
    get_remediations_for_analysis,
    list_remediation_capabilities,
    simulation_timestamp,
)
from ..storage.database import (
    get_analysis_bundle,
    get_simulation_result,
    save_simulation_result,
    save_analysis_result,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/remediation", tags=["remediation simulation"])


@router.get("/capabilities", response_model=list[RemediationDefinition])
def remediation_capabilities(vendor: str | None = None, control_id: str | None = None) -> list[RemediationDefinition]:
    return list_remediation_capabilities(vendor, control_id)


def _load_analysis(analysis_id: str) -> tuple[AnalysisResponse, SecurityIR]:
    bundle = get_analysis_bundle(analysis_id)
    if bundle is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, ApiErrorCode.ANALYSIS_NOT_FOUND, "The analysis was not found.")
    try:
        analysis = AnalysisResponse.model_validate(bundle["response"])
        if not bundle["security_ir"]:
            raise ValueError("missing Security IR snapshot")
        security_ir = SecurityIR.model_validate(bundle["security_ir"])
    except (TypeError, ValueError) as exc:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.SIMULATION_FAILED, "The analysis cannot be used for simulation.") from exc
    return analysis, security_ir


@router.get("/{analysis_id}", response_model=RemediationResponse)
def list_remediations(analysis_id: str) -> RemediationResponse:
    analysis, _ = _load_analysis(analysis_id)
    return RemediationResponse(
        analysis_id=analysis_id,
        remediations=get_remediations_for_analysis(analysis),
    )


@router.post("/{analysis_id}/simulate", response_model=SimulationResponse)
def simulate_remediation(analysis_id: str, request: SimulationRequest, http_request: Request) -> SimulationResponse:
    analysis, security_ir = _load_analysis(analysis_id)
    try:
        remediation = get_remediation(analysis, request.remediation_id)
    except RemediationError as exc:
        raise ApiError(status.HTTP_404_NOT_FOUND, ApiErrorCode.REMEDIATION_NOT_AVAILABLE, str(exc)) from exc

    simulation_id = str(uuid4())
    try:
        application = apply_simulation(
            security_ir,
            remediation,
            simulation_id=simulation_id,
            original_analysis_id=analysis_id,
        )
        controls = load_demo_controls()
        evaluations = DeterministicControlEngine().evaluate_all(
            application.security_ir,
            controls,
        )
        evidence = [
            item
            for evaluation in evaluations
            for item in build_evidence(application.security_ir, evaluation)
        ]
    except RemediationError as exc:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.SIMULATION_FAILED, str(exc)) from exc
    except CatalogueError:
        raise
    except Exception as exc:
        logger.exception("Remediation simulation failed for %s", analysis_id)
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.SIMULATION_FAILED, "The remediation simulation failed safely.") from exc

    after_results = {
        evaluation.control_id: evaluation
        for evaluation in evaluations
    }
    before_result = next(
        (result.result for result in analysis.results if result.control_id == remediation.control_id),
        None,
    )
    after_result = after_results.get(remediation.control_id)
    if before_result is None or after_result is None:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.SIMULATION_FAILED, "The selected control result is unavailable.")

    result = SimulationResponse(
        simulation_id=simulation_id,
        parent_analysis_id=analysis_id,
        remediation_id=remediation.remediation_id,
        control_id=remediation.control_id,
        before_result=before_result,
        after_result=after_result.result,
        simulated_changes=application.changes,
        simulation_only=True,
        created_at=simulation_timestamp(),
        results=[
            ControlResultSummary(
                control_id=evaluation.control_id,
                control_name=evaluation.control_name,
                diagnostic_of=next(c.diagnostic_of for c in controls if c.control_id == evaluation.control_id),
                result=evaluation.result,
                expected=evaluation.expected,
                actual=evaluation.actual,
                explanation=evaluation.explanation,
                severity=evaluation.severity,
                category=evaluation.category,
                framework_mappings=evaluation.framework_mappings,
            )
            for evaluation in evaluations
        ],
        evidence=evidence,
        message=f"Simulation completed for {remediation.remediation_id}; no production device was modified.",
        original_configuration_fingerprint=analysis.configuration.content_sha256 if analysis.configuration else None,
        target_vendor=analysis.vendor,
        initiated_by=getattr(http_request.state, "actor", {}).get("user_id"),
    )

    try:
        save_simulation_result(
            simulation_id=simulation_id,
            parent_analysis_id=analysis_id,
            remediation_id=remediation.remediation_id,
            response=result.model_dump(mode="json"),
            actor_id=getattr(http_request.state, "actor", {}).get("user_id"),
        )
    except Exception as exc:
        logger.exception("Could not persist remediation simulation %s", simulation_id)
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.STORAGE_FAILURE, "The simulation result could not be stored.") from exc

    return result


@router.post("/simulations/{simulation_id}/reanalyze", response_model=AnalysisResponse)
def reanalyze_simulation(simulation_id: str, http_request: Request) -> AnalysisResponse:
    """Explicitly evaluate a stored simulation; simulation itself never finalizes compliance."""
    raw = get_simulation_result(simulation_id)
    if raw is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, ApiErrorCode.REMEDIATION_NOT_AVAILABLE, "Simulation was not found.")
    simulation = SimulationResponse.model_validate(raw)
    original, security_ir = _load_analysis(simulation.parent_analysis_id)
    try:
        remediation = get_remediation(original, simulation.remediation_id)
        application = apply_simulation(security_ir, remediation, simulation_id=simulation_id, original_analysis_id=original.analysis_id)
        controls = load_demo_controls()
        evaluations = DeterministicControlEngine().evaluate_all(application.security_ir, controls)
        evidence = [item for evaluation in evaluations for item in build_evidence(application.security_ir, evaluation)]
    except (RemediationError, CatalogueError) as exc:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.SIMULATION_FAILED, "The stored simulation cannot be re-analyzed safely.") from exc
    response = AnalysisResponse(
        analysis_id=str(uuid4()), filename=original.filename, vendor=original.vendor, device=original.device,
        configuration=original.configuration, parent_analysis_id=original.analysis_id, reanalyzed=True,
        results=[ControlResultSummary(
            control_id=e.control_id, control_name=e.control_name,
            diagnostic_of=next(c.diagnostic_of for c in controls if c.control_id == e.control_id),
            result=e.result, expected=e.expected, actual=e.actual, explanation=e.explanation,
            severity=e.severity, category=e.category, framework_mappings=e.framework_mappings,
        ) for e in evaluations],
        evidence=evidence, unknown_patterns=application.security_ir.unknown_patterns,
        recognized_patterns=application.security_ir.recognized_patterns,
        message=f"Explicit deterministic re-analysis completed for simulation {simulation_id}; this is the final simulated compliance result.",
    )
    save_analysis_result(analysis_id=response.analysis_id, filename=response.filename, vendor=response.vendor, response=response.model_dump(mode="json"), security_ir=application.security_ir.model_dump(mode="json"), actor_id=getattr(http_request.state, "actor", {}).get("user_id"))
    return response
