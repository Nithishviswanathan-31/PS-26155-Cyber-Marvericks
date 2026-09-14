from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .evidence import EvidenceRecord
from .enums import ComplianceResult, PatternStatus
from .security_ir import RecognizedPattern, SecurityIR, SourceLocation, UnknownPattern


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


class ControlDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    name: str
    description: str
    expected_value: str
    evaluation: ControlEvaluation
    evidence_rule: dict[str, Any] = Field(default_factory=dict)
    remediation: dict[str, str] = Field(default_factory=dict)


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


class ControlResultSummary(BaseModel):
    """Compact control result returned alongside detailed evidence."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    control_name: str
    result: ComplianceResult
    expected: Any
    actual: Any
    explanation: str


class AnalysisResponse(BaseModel):
    """Response contract for one uploaded configuration analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    filename: str
    vendor: str
    device: AnalysisDeviceResponse
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
