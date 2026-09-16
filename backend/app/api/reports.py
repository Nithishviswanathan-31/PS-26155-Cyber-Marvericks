import logging
from uuid import uuid4

from fastapi import APIRouter, Response, status, Request

from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.mapping import MappingVersion
from ..domain.remediation import SimulationResponse
from ..domain.schemas import AnalysisResponse
from ..services.report_service import ReportGenerationError, generate_analysis_pdf
from ..storage.database import (
    get_analysis_bundle,
    get_latest_simulation_for_analysis,
    get_mapping_versions,
    append_integrity_record,
    get_latest_integrity_record,
    verify_integrity_record,
    save_report_metadata,
    list_report_metadata,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{analysis_id}")
def report_history(analysis_id: str):
    return {"items": list_report_metadata(analysis_id)}


@router.get("/{analysis_id}/pdf")
def generate_pdf_report(analysis_id: str, request: Request) -> Response:
    """Export stored analysis data without recalculating compliance."""

    bundle = get_analysis_bundle(analysis_id)
    if bundle is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, ApiErrorCode.ANALYSIS_NOT_FOUND, "The analysis was not found.")

    try:
        analysis = AnalysisResponse.model_validate(bundle["response"])
    except (TypeError, ValueError) as exc:
        raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.REPORT_DATA_INCOMPLETE, "The stored analysis data is incomplete for reporting.") from exc

    mapping = None
    if analysis.reanalyzed and analysis.recognized_patterns and analysis.mapping_id and analysis.mapping_version:
        versions = get_mapping_versions(analysis.recognized_patterns[0].pattern_id)
        matching = next(
            (
                item
                for item in versions
                if item.get("mapping_id") == analysis.mapping_id
                and item.get("version") == analysis.mapping_version
            ),
            None,
        )
        if matching is None:
            raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.REPORT_DATA_INCOMPLETE, "The approved mapping lineage is unavailable for this report.")
        try:
            mapping = MappingVersion.model_validate(matching)
        except (TypeError, ValueError) as exc:
            raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.REPORT_DATA_INCOMPLETE, "The approved mapping data is invalid for this report.") from exc

    simulation = None
    raw_simulation = get_latest_simulation_for_analysis(analysis_id)
    if raw_simulation is not None:
        try:
            simulation = SimulationResponse.model_validate(raw_simulation)
        except (TypeError, ValueError) as exc:
            raise ApiError(status.HTTP_409_CONFLICT, ApiErrorCode.REPORT_DATA_INCOMPLETE, "The simulation data is invalid for this report.") from exc

    analysis_integrity = verify_integrity_record("ANALYSIS", analysis_id)
    analysis_record = get_latest_integrity_record("ANALYSIS", analysis_id)
    report_id = f"report-{uuid4().hex[:12]}"
    report_record = append_integrity_record(
        "REPORT", report_id,
        {"analysis_id": analysis_id, "analysis_hash": analysis_record["content_hash"] if analysis_record else None,
         "mapping_id": analysis.mapping_id, "mapping_version": analysis.mapping_version,
         "simulation_id": simulation.simulation_id if simulation else None},
        actor_id=getattr(request.state, "actor", {}).get("user_id"),
    )
    integrity = {"status": analysis_integrity["status"], "analysis_hash": analysis_record["content_hash"] if analysis_record else None, "ledger_record_id": report_record["integrity_record_id"]}
    report_metadata = save_report_metadata(report_id=report_id, analysis_id=analysis_id, generated_by=getattr(request.state, "actor", {}).get("user_id"), integrity_record_id=report_record["integrity_record_id"], metadata={"analysis_hash": integrity["analysis_hash"], "integrity_status": integrity["status"], "mapping_id": analysis.mapping_id, "mapping_version": analysis.mapping_version, "simulation_id": simulation.simulation_id if simulation else None})
    integrity["report_version"] = report_metadata["report_version"]
    try:
        pdf = generate_analysis_pdf(
            analysis, mapping=mapping, simulation=simulation, integrity=integrity,
            report_id=report_metadata["report_id"], generated_at=report_metadata["generated_at"],
        )
    except ReportGenerationError as exc:
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.REPORT_GENERATION_FAILED, str(exc)) from exc
    except Exception as exc:
        logger.exception("Report generation failed for %s", analysis_id)
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.REPORT_GENERATION_FAILED, "The PDF report could not be generated safely.") from exc

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="ps26155-report-{analysis_id[:12]}.pdf"'},
    )
