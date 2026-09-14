from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from .enums import ComplianceResult
from .evidence import EvidenceRecord
from .schemas import ControlResultSummary


RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


class RemediationDefinition(BaseModel):
    """A deterministic, reviewed recommendation; never an execution plan."""

    model_config = ConfigDict(extra="forbid")

    remediation_id: str = Field(min_length=1)
    control_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    commands: list[str] = Field(min_length=1)
    target_properties: list[str] = Field(min_length=1)
    expected_state: dict[str, StrictBool] = Field(min_length=1)
    risk_level: RiskLevel
    simulation_only: Literal[True] = True


class RemediationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    simulation_only: Literal[True] = True
    remediations: list[RemediationDefinition] = Field(default_factory=list)


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remediation_id: str = Field(min_length=1)


class SimulatedChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    property: str = Field(min_length=1)
    before_value: Any
    after_value: Any
    change_source: Literal["SIMULATED_REMEDIATION"] = "SIMULATED_REMEDIATION"


class SimulationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    simulation_id: str
    parent_analysis_id: str
    remediation_id: str
    control_id: str
    before_result: ComplianceResult
    after_result: ComplianceResult
    simulated_changes: list[SimulatedChange] = Field(default_factory=list)
    simulation_only: Literal[True] = True
    created_at: str
    results: list[ControlResultSummary] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    message: str
