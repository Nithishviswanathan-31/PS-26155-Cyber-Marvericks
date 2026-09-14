from enum import StrEnum
from typing import Any


class ApiErrorCode(StrEnum):
    """Stable machine-readable codes for expected demo API failures."""

    ANALYSIS_NOT_FOUND = "ANALYSIS_NOT_FOUND"
    UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
    MALFORMED_CONFIGURATION = "MALFORMED_CONFIGURATION"
    UNKNOWN_PATTERN = "UNKNOWN_PATTERN"
    NO_ACTIVE_MAPPING = "NO_ACTIVE_MAPPING"
    INVALID_MAPPING = "INVALID_MAPPING"
    INACTIVE_MAPPING = "INACTIVE_MAPPING"
    REJECTED_MAPPING = "REJECTED_MAPPING"
    REANALYSIS_FAILED = "REANALYSIS_FAILED"
    REMEDIATION_NOT_FOUND = "REMEDIATION_NOT_FOUND"
    REMEDIATION_NOT_AVAILABLE = "REMEDIATION_NOT_AVAILABLE"
    UNSUPPORTED_REMEDIATION = "UNSUPPORTED_REMEDIATION"
    SIMULATION_FAILED = "SIMULATION_FAILED"
    SIMULATION_ONLY_VIOLATION = "SIMULATION_ONLY_VIOLATION"
    REPORT_GENERATION_FAILED = "REPORT_GENERATION_FAILED"
    REPORT_NOT_AVAILABLE = "REPORT_NOT_AVAILABLE"
    REPORT_DATA_INCOMPLETE = "REPORT_DATA_INCOMPLETE"
    DEMO_RESET_DISABLED = "DEMO_RESET_DISABLED"
    STORAGE_FAILURE = "STORAGE_FAILURE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"


class ApiError(Exception):
    """Expected API failure with a stable code and user-safe message."""

    def __init__(self, status_code: int, code: ApiErrorCode, message: str, detail: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.detail = detail


def error_payload(code: ApiErrorCode | str, message: str, detail: Any = None) -> dict[str, Any]:
    """Return the backwards-compatible ``detail`` plus a stable error code."""

    payload: dict[str, Any] = {"detail": message, "error_code": str(code)}
    if detail is not None:
        payload["errors"] = detail
    return payload
