from enum import Enum


class ComplianceResult(str, Enum):
    """Possible deterministic compliance outcomes."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class PatternStatus(str, Enum):
    """Lifecycle of a configuration pattern in the learning workflow."""

    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    SUGGESTED = "SUGGESTED"
    APPROVED = "APPROVED"
    RECOGNIZED = "RECOGNIZED"
