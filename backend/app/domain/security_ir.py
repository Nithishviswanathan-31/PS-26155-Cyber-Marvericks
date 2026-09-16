from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import PatternStatus


class SourceLocation(BaseModel):
    """Traceability information for a normalized property or pattern."""

    model_config = ConfigDict(extra="forbid")

    source_file: str = Field(min_length=1)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    raw_excerpt: str | None = None

    @field_validator("source_file")
    @classmethod
    def source_file_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("source_file cannot be empty")
        return value

    @model_validator(mode="after")
    def line_range_must_be_ordered(self) -> "SourceLocation":
        if self.line_start is not None and self.line_end is not None:
            if self.line_end < self.line_start:
                raise ValueError("line_end cannot be less than line_start")
        return self


class MappingProvenance(BaseModel):
    """Traceability for a property introduced by an approved mapping."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["APPROVED_MAPPING"] = "APPROVED_MAPPING"
    mapping_id: str = Field(min_length=1)
    mapping_version: int = Field(ge=1)
    original_pattern: str = Field(min_length=1)
    original_location: SourceLocation | None = None


class SimulationProvenance(BaseModel):
    """Traceability for a value introduced only in a remediation simulation."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["SIMULATED_REMEDIATION"] = "SIMULATED_REMEDIATION"
    simulation_id: str = Field(min_length=1)
    remediation_id: str = Field(min_length=1)
    original_analysis_id: str = Field(min_length=1)
    original_value: Any
    simulated_value: Any
    original_location: SourceLocation | None = None


class DeviceInfo(BaseModel):
    """Basic device metadata shared by all vendor parsers."""

    model_config = ConfigDict(extra="forbid")

    vendor: str = Field(min_length=1)
    version: str | None = None
    hostname: str | None = None
    device_model: str | None = None
    serial_number: str | None = None
    device_id: str | None = None
    platform: str | None = None
    metadata_provenance: dict[str, SourceLocation] = Field(default_factory=dict)

    @field_validator("vendor")
    @classmethod
    def vendor_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("vendor cannot be empty")
        return value


class UnknownPattern(BaseModel):
    """A raw configuration pattern not yet mapped to the Security IR."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str = Field(min_length=1)
    raw_pattern: str = Field(min_length=1)
    status: PatternStatus = PatternStatus.UNKNOWN
    location: SourceLocation | None = None
    source_file: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    reason: str | None = None
    context: str | None = None
    candidate_mapping: dict[str, Any] | None = None

    @model_validator(mode="after")
    def normalize_source_location(self) -> "UnknownPattern":
        if self.location is None:
            if self.source_file is None:
                raise ValueError("unknown pattern requires source_file or location")
            self.location = SourceLocation(
                source_file=self.source_file,
                line_start=self.line_start,
                line_end=self.line_end,
            )
        else:
            if self.source_file is None:
                self.source_file = self.location.source_file
            if self.line_start is None:
                self.line_start = self.location.line_start
            if self.line_end is None:
                self.line_end = self.location.line_end

        if self.line_start is not None and self.line_end is not None:
            if self.line_end < self.line_start:
                raise ValueError("line_end cannot be less than line_start")
        return self


class PropertyTrace(BaseModel):
    """Resolved value plus the source location that produced it."""

    model_config = ConfigDict(extra="forbid")

    property: str = Field(min_length=1)
    value: Any
    provenance: SourceLocation | None = None
    mapping_provenance: MappingProvenance | None = None
    simulation_provenance: SimulationProvenance | None = None


class RecognizedPattern(BaseModel):
    """Explicit recognition state created by approved-mapping application."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str = Field(min_length=1)
    state: Literal["RECOGNIZED_VIA_APPROVED_MAPPING"] = "RECOGNIZED_VIA_APPROVED_MAPPING"
    original_status: PatternStatus = PatternStatus.UNKNOWN
    raw_pattern: str = Field(min_length=1)
    mapping_id: str = Field(min_length=1)
    mapping_version: int = Field(ge=1)
    source_location: SourceLocation | None = None


class SecurityIR(BaseModel):
    """Small vendor-neutral contract used by later analysis stages."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "0.1"
    device: DeviceInfo
    normalized_properties: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, SourceLocation] = Field(default_factory=dict)
    mapping_provenance: dict[str, MappingProvenance] = Field(default_factory=dict)
    simulation_provenance: dict[str, SimulationProvenance] = Field(default_factory=dict)
    unknown_patterns: list[UnknownPattern] = Field(default_factory=list)
    recognized_patterns: list[RecognizedPattern] = Field(default_factory=list)

    @field_validator("normalized_properties")
    @classmethod
    def property_keys_must_not_be_blank(cls, value: dict[str, Any]) -> dict[str, Any]:
        if any(not key.strip() for key in value):
            raise ValueError("normalized property keys cannot be empty")
        return value

    @field_validator("provenance")
    @classmethod
    def provenance_keys_must_not_be_blank(
        cls, value: dict[str, SourceLocation]
    ) -> dict[str, SourceLocation]:
        if any(not key.strip() for key in value):
            raise ValueError("provenance keys cannot be empty")
        return value

    @field_validator("mapping_provenance")
    @classmethod
    def mapping_provenance_keys_must_not_be_blank(
        cls, value: dict[str, MappingProvenance]
    ) -> dict[str, MappingProvenance]:
        if any(not key.strip() for key in value):
            raise ValueError("mapping provenance keys cannot be empty")
        return value

    @field_validator("simulation_provenance")
    @classmethod
    def simulation_provenance_keys_must_not_be_blank(
        cls, value: dict[str, SimulationProvenance]
    ) -> dict[str, SimulationProvenance]:
        if any(not key.strip() for key in value):
            raise ValueError("simulation provenance keys cannot be empty")
        return value

    def trace_property(self, property_name: str) -> PropertyTrace | None:
        """Return the normalized value and its source, if the property exists."""

        if property_name not in self.normalized_properties:
            return None
        return PropertyTrace(
            property=property_name,
            value=self.normalized_properties[property_name],
            provenance=self.provenance.get(property_name),
            mapping_provenance=self.mapping_provenance.get(property_name),
            simulation_provenance=self.simulation_provenance.get(property_name),
        )
