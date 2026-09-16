import logging

from fastapi import APIRouter, File, Form, UploadFile, status, Request

from ..config import CatalogueError, load_demo_controls
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.schemas import AnalysisResponse
from ..services.analysis_service import analyze_configuration_bytes
from ..storage.database import get_analysis_result


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["analysis"])

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_configuration(request: Request, file: UploadFile = File(...), device_id: str | None = Form(default=None)) -> AnalysisResponse:
    """Analyze one supported real-vendor or synthetic AstraNet configuration file."""

    try:
        actor = getattr(request.state, "actor", {})
        return analyze_configuration_bytes(await file.read(1 * 1024 * 1024 + 1), file.filename or "", device_id, load_demo_controls(), actor_id=actor.get("user_id"))
    except (ApiError, CatalogueError):
        raise
    except Exception as exc:
        logger.exception("Unexpected configuration analysis failure")
        raise ApiError(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            ApiErrorCode.INTERNAL_ERROR,
            "The configuration analysis failed due to an internal error.",
        ) from exc
    finally:
        await file.close()


@router.get("/analyze/{analysis_id}", response_model=AnalysisResponse)
def read_analysis(analysis_id: str) -> AnalysisResponse:
    stored = get_analysis_result(analysis_id)
    if stored is None:
        raise ApiError(404, ApiErrorCode.ANALYSIS_NOT_FOUND, "Analysis was not found.")
    return AnalysisResponse.model_validate(stored)
