from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .enums import ComplianceResult
from .security_ir import SecurityIR, SourceLocation

if TYPE_CHECKING:
    from .schemas import ControlEvaluationResult


class EvidenceRecord(BaseModel):
    """Reusable evidence record for a normalized property evaluation."""

    model_config = ConfigDict(extra="forbid")

    property: str = Field(min_length=1)
    expected: Any
    actual: Any
    result: ComplianceResult
    source_file: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    raw_excerpt: str | None = None
    explanation: str
    control_id: str | None = None
    control_name: str | None = None
    vendor: str | None = None
    configuration_version: str | None = None
    condition_result: ComplianceResult | None = None
    control_explanation: str | None = None
    evidence_source: str | None = None
    mapping_id: str | None = None
    mapping_version: int | None = Field(default=None, ge=1)
    original_pattern: str | None = None
    original_source_file: str | None = None
    original_line_start: int | None = Field(default=None, ge=1)
    original_line_end: int | None = Field(default=None, ge=1)
    original_raw_excerpt: str | None = None
    simulation_id: str | None = None
    remediation_id: str | None = None
    original_analysis_id: str | None = None
    before_value: Any = None
    after_value: Any = None

    @model_validator(mode="after")
    def line_range_must_be_ordered(self) -> "EvidenceRecord":
        if self.line_start is not None and self.line_end is not None:
            if self.line_end < self.line_start:
                raise ValueError("line_end cannot be less than line_start")
        return self

    @classmethod
    def from_trace(
        cls,
        *,
        property_name: str,
        expected: Any,
        actual: Any,
        result: ComplianceResult,
        provenance: SourceLocation | None,
        explanation: str,
    ) -> "EvidenceRecord":
        """Preserve the P0.3 construction interface for control-engine output."""

        return cls(
            property=property_name,
            expected=expected,
            actual=actual,
            result=result,
            source_file=provenance.source_file if provenance else None,
            line_start=provenance.line_start if provenance else None,
            line_end=provenance.line_end if provenance else None,
            raw_excerpt=provenance.raw_excerpt if provenance else None,
            explanation=explanation,
            condition_result=result,
        )


# Backward-compatible name used by the P0.3 control engine.
ControlEvidence = EvidenceRecord


def build_evidence(
    security_ir: SecurityIR,
    control_evaluation: "ControlEvaluationResult",
) -> list[EvidenceRecord]:
    """Build traceable evidence without changing the deterministic result."""

    records: list[EvidenceRecord] = []
    for condition_evidence in control_evaluation.evidence:
        trace = security_ir.trace_property(condition_evidence.property)
        provenance = trace.provenance if trace else None
        simulation = trace.simulation_provenance if trace else None
        mapping = trace.mapping_provenance if trace else None
        original_location = (
            simulation.original_location
            if simulation
            else mapping.original_location
            if mapping
            else None
        )
        actual = trace.value if trace else None
        condition_result = condition_evidence.condition_result or condition_evidence.result

        records.append(
            EvidenceRecord(
                property=condition_evidence.property,
                expected=condition_evidence.expected,
                actual=actual,
                result=control_evaluation.result,
                source_file=provenance.source_file if provenance and not simulation else None,
                line_start=provenance.line_start if provenance and not simulation else None,
                line_end=provenance.line_end if provenance and not simulation else None,
                raw_excerpt=provenance.raw_excerpt if provenance and not simulation else None,
                explanation=condition_evidence.explanation,
                control_id=control_evaluation.control_id,
                control_name=control_evaluation.control_name,
                vendor=security_ir.device.vendor,
                configuration_version=security_ir.device.version,
                condition_result=condition_result,
                control_explanation=control_evaluation.explanation,
                evidence_source=(
                    "SIMULATED_REMEDIATION" if simulation
                    else "APPROVED_MAPPING" if mapping else "CONFIGURATION"
                ) if trace else None,
                mapping_id=(trace.mapping_provenance.mapping_id if trace and trace.mapping_provenance else None),
                mapping_version=(
                    trace.mapping_provenance.mapping_version
                    if trace and trace.mapping_provenance
                    else None
                ),
                original_pattern=(
                    trace.mapping_provenance.original_pattern
                    if trace and trace.mapping_provenance
                    else None
                ),
                original_source_file=(
                    original_location.source_file
                    if original_location
                    else None
                ),
                original_line_start=(
                    original_location.line_start
                    if original_location
                    else None
                ),
                original_line_end=(
                    original_location.line_end
                    if original_location
                    else None
                ),
                original_raw_excerpt=(
                    original_location.raw_excerpt
                    if original_location
                    else None
                ),
                simulation_id=simulation.simulation_id if simulation else None,
                remediation_id=simulation.remediation_id if simulation else None,
                original_analysis_id=simulation.original_analysis_id if simulation else None,
                before_value=simulation.original_value if simulation else None,
                after_value=simulation.simulated_value if simulation else None,
            )
        )

    return records
