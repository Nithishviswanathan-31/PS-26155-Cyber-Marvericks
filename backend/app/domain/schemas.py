from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StringConstraints, model_validator

from .evidence import EvidenceRecord
from .enums import ComplianceResult, PatternStatus
from .security_ir import RecognizedPattern, SecurityIR, SourceLocation, UnknownPattern
from .inventory import Configuration


class HealthResponse(BaseModel):
    status: Literal["ok"]


class DemoResetResponse(BaseModel):
    """Result of the local development/demo database reset."""

    status: Literal["reset"]
    demo_only: Literal[True] = True
    deleted: dict[str, int]
    message: str


class ControlCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    operator: str
    expected: Any


class ControlEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    conditions: list[ControlCondition] = Field(default_factory=list)


ControlCategory = Literal[
    "MANAGEMENT_ACCESS", "LOGGING_MONITORING", "AUTHENTICATION",
    "CREDENTIAL_PROTECTION", "TIME_SYNCHRONIZATION", "NETWORK_SECURITY",
    "CONFIGURATION_SECURITY", "CRYPTOGRAPHY",
]
ControlSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ControlVendor = Literal["cisco_iosxe", "fortigate_fortios", "paloalto_panos", "astranet"]
NonBlankText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


FrameworkMappingStatus = Literal["VERIFIED", "PROTOTYPE", "INTERNAL"]


class FrameworkMapping(BaseModel):
    """Informational reference; presence does not verify an official mapping."""

    model_config = ConfigDict(extra="forbid")

    framework_name: NonBlankText
    framework_version: NonBlankText | None = None
    reference_id: NonBlankText
    title: NonBlankText | None = None
    description: NonBlankText | None = None
    mapping_status: FrameworkMappingStatus = "VERIFIED"


class EvidenceRequirements(BaseModel):
    """Advisory presentation metadata, not an evidence filter or evaluation input."""

    model_config = ConfigDict(extra="forbid")

    include_paths: list[NonBlankText] = Field(default_factory=list)
    display_fields: list[Literal[
        "actual", "expected", "source_file", "line_start", "line_end",
        "raw_excerpt", "evidence_source", "result", "condition_result",
    ]] = Field(default_factory=lambda: [
        "actual", "expected", "source_file", "line_start", "line_end",
        "raw_excerpt", "evidence_source", "result", "condition_result",
    ])


class ControlDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    name: str
    description: str
    expected_value: str
    evaluation: ControlEvaluation
    evidence_rule: dict[str, Any] = Field(default_factory=dict)
    remediation: dict[str, str] = Field(default_factory=dict)
    category: ControlCategory | None = None
    severity: ControlSeverity | None = None
    enabled: StrictBool = True
    applicable_vendors: list[ControlVendor] = Field(default_factory=list)
    framework_mappings: list[FrameworkMapping] = Field(default_factory=list)
    evidence_requirements: EvidenceRequirements | None = None
    remediation_reference: dict[ControlVendor, NonBlankText] | None = None
    diagnostic_of: NonBlankText | None = None

    @model_validator(mode="after")
    def validate_evidence_requirements(self) -> "ControlDefinition":
        # Legacy definitions keep their original shape and evaluation behavior.
        if self.evidence_requirements is not None:
            paths = self.evidence_requirements.include_paths
            conditions = {condition.path for condition in self.evaluation.conditions}
            if len(paths) != len(set(paths)) or set(paths) != conditions:
                raise ValueError("evidence requirements must cover exactly the evaluation properties")
            legacy_paths = self.evidence_rule.get("include_paths")
            if legacy_paths is not None and set(legacy_paths) != set(paths):
                raise ValueError("evidence_rule and evidence_requirements must agree")
        return self


class ControlEvaluationResult(BaseModel):
    """Deterministic result returned for one YAML control."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    control_name: str
    result: ComplianceResult
    expected: Any
    actual: Any
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    explanation: str
    remediation: dict[str, str] = Field(default_factory=dict)
    severity: ControlSeverity | None = None
    category: ControlCategory | None = None
    framework_mappings: list[FrameworkMapping] = Field(default_factory=list)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ControlEvaluationResult):
            return False
        return (
            self.control_id == other.control_id
            and self.control_name == other.control_name
            and self.result == other.result
            and self.expected == other.expected
            and self.actual == other.actual
            and self.evidence == other.evidence
            and self.explanation == other.explanation
            and self.remediation == other.remediation
        )


# Backward-compatible P0.3 import name.
ControlEvidence = EvidenceRecord


class ContractExample(BaseModel):
    """Small aggregate used by tests to prove contracts compose correctly."""

    result: ComplianceResult
    pattern_status: PatternStatus
    security_ir: SecurityIR


class AnalysisDeviceResponse(BaseModel):
    """Device metadata exposed by the configuration-analysis API."""

    model_config = ConfigDict(extra="forbid")

    hostname: str | None = None
    version: str | None = None
    device_model: str | None = None
    serial_number: str | None = None
    device_id: str | None = None
    platform: str | None = None


class ControlResultSummary(BaseModel):
    """Compact control result returned alongside detailed evidence."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    control_name: str
    result: ComplianceResult
    expected: Any
    actual: Any
    explanation: str
    diagnostic_of: str | None = None
    severity: ControlSeverity | None = None
    category: ControlCategory | None = None
    framework_mappings: list[FrameworkMapping] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    """Response contract for one uploaded configuration analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    filename: str
    vendor: str
    device: AnalysisDeviceResponse
    configuration: Configuration | None = None
    results: list[ControlResultSummary] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    unknown_patterns: list[UnknownPattern] = Field(default_factory=list)
    recognized_patterns: list[RecognizedPattern] = Field(default_factory=list)
    parent_analysis_id: str | None = None
    reanalyzed: bool = False
    mapping_id: str | None = None
    mapping_version: int | None = Field(default=None, ge=1)
    reanalyzed_at: datetime | None = None
    message: str | None = None
