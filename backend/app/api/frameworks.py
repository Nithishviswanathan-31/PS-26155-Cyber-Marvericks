from fastapi import APIRouter, status

from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.frameworks import FrameworkInfo, get_framework_info, get_framework_registry

router = APIRouter(prefix="/api/frameworks", tags=["frameworks"])


@router.get("", response_model=list[FrameworkInfo])
def list_frameworks() -> list[FrameworkInfo]:
    """List supported compliance frameworks and their metadata."""
    return get_framework_registry()


@router.get("/{framework_id}", response_model=FrameworkInfo)
def read_framework(framework_id: str) -> FrameworkInfo:
    """Retrieve metadata for a specific compliance framework."""
    info = get_framework_info(framework_id)
    if info is None:
        raise ApiError(
            status.HTTP_404_NOT_FOUND,
            ApiErrorCode.VALIDATION_ERROR,
            f"Framework '{framework_id}' was not found in the registry.",
        )
    return info
