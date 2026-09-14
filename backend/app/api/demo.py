from fastapi import APIRouter, status

from ..config import is_demo_reset_enabled
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.schemas import DemoResetResponse
from ..storage.database import reset_demo_database


router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.post("/reset", response_model=DemoResetResponse)
def reset_demo() -> DemoResetResponse:
    """Reset local demo records; this route is unavailable in production."""

    if not is_demo_reset_enabled():
        raise ApiError(
            status.HTTP_403_FORBIDDEN,
            ApiErrorCode.DEMO_RESET_DISABLED,
            "Demo reset is disabled outside local development mode.",
        )
    try:
        deleted = reset_demo_database()
    except Exception as exc:
        raise ApiError(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            ApiErrorCode.STORAGE_FAILURE,
            "The demo database could not be reset.",
        ) from exc
    return DemoResetResponse(
        status="reset",
        deleted=deleted,
        message="Development/demo records were reset. Database schema was preserved.",
    )
