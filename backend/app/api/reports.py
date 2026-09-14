import logging

from fastapi import APIRouter, Response, status

from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.mapping import MappingVersion
from ..domain.remediation import SimulationResponse
from ..domain.schemas import AnalysisResponse
from ..services.report_service import ReportGenerationError, generate_analysis_pdf
from ..storage.database import (
    get_analysis_bundle,
    get_latest_simulation_for_analysis,
    get_mapping_versions,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{analysis_id}/pdf")
def generate_pdf_report(analysis_id: str) -> Response:
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

    try:
        pdf = generate_analysis_pdf(analysis, mapping=mapping, simulation=simulation)
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
