from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from .security_ir import UnknownPattern


SUPPORTED_MAPPING_PROPERTIES = frozenset(
    {
        "management.ssh_enabled",
        "management.telnet_enabled",
        "logging.enabled",
        "password_protection.enabled",
        "time_sync.ntp_enabled",
    }
)


class MappingStatus(str, Enum):
    """Lifecycle states for stored candidate and approved mappings."""

    SUGGESTED = "SUGGESTED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    INACTIVE = "INACTIVE"


def validate_semantic_mapping(value: dict[str, StrictBool]) -> dict[str, StrictBool]:
    """Allow only known vendor-neutral properties and strict boolean values."""

    unsupported = set(value) - SUPPORTED_MAPPING_PROPERTIES
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise ValueError(f"unsupported normalized mapping property: {names}")
    return value


class CandidateMappingSuggestion(BaseModel):
    """Schema-validated candidate meaning returned by the controlled adapter."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str = Field(min_length=1)
    status: Literal[MappingStatus.SUGGESTED] = MappingStatus.SUGGESTED
    confidence: float = Field(ge=0.0, le=1.0)
    semantic_mapping: dict[str, StrictBool] = Field(min_length=1)
    reasoning: str = Field(min_length=1)
    requires_human_approval: Literal[True] = True

    @field_validator("pattern_id", "reasoning")
    @classmethod
    def text_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("text fields cannot be blank")
        return value

    @field_validator("semantic_mapping")
    @classmethod
    def mapping_must_be_supported(
        cls, value: dict[str, StrictBool]
    ) -> dict[str, StrictBool]:
        return validate_semantic_mapping(value)


class MappingDecisionRequest(BaseModel):
    """Explicit reviewer input for approve or correct-and-approve."""

    model_config = ConfigDict(extra="forbid")

    reviewer_id: str = Field(min_length=1)
    semantic_mapping: dict[str, StrictBool] = Field(min_length=1)

    @field_validator("reviewer_id")
    @classmethod
    def reviewer_id_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reviewer_id cannot be blank")
        return value

    @field_validator("semantic_mapping")
    @classmethod
    def mapping_must_be_supported(
        cls, value: dict[str, StrictBool]
    ) -> dict[str, StrictBool]:
        return validate_semantic_mapping(value)


class RejectMappingRequest(BaseModel):
    """Explicit reviewer input for rejecting a candidate."""

    model_config = ConfigDict(extra="forbid")

    reviewer_id: str = Field(min_length=1)
    reason: str | None = None

    @field_validator("reviewer_id")
    @classmethod
    def reviewer_id_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reviewer_id cannot be blank")
        return value


class MappingVersion(BaseModel):
    """One immutable version in a mapping's local approval history."""

    model_config = ConfigDict(extra="forbid")

    mapping_id: str = Field(min_length=1)
    pattern_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    pattern_signature: str = Field(min_length=1)
    proposed_mapping: dict[str, StrictBool] = Field(default_factory=dict)
    approved_mapping: dict[str, StrictBool] | None = None
    status: MappingStatus
    version: int = Field(ge=1)
    reviewer_id: str | None = None
    action: str = Field(min_length=1)
    created_at: datetime
    updated_at: datetime
    active: bool = False

    @field_validator("proposed_mapping")
    @classmethod
    def proposed_mapping_must_be_supported(
        cls, value: dict[str, StrictBool]
    ) -> dict[str, StrictBool]:
        return validate_semantic_mapping(value)

    @field_validator("approved_mapping")
    @classmethod
    def approved_mapping_must_be_supported(
        cls, value: dict[str, StrictBool] | None
    ) -> dict[str, StrictBool] | None:
        if value is not None:
            return validate_semantic_mapping(value)
        return value


class MappingReviewResponse(BaseModel):
    """Unknown pattern plus any stored mapping state for reviewer display."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    vendor: str
    pattern: UnknownPattern
    suggestion: CandidateMappingSuggestion | None = None
    latest_mapping: MappingVersion | None = None


class MappingDecisionResponse(BaseModel):
    """Result of a human mapping decision, with compliance explicitly unchanged."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    pattern_status: Literal["UNKNOWN"] = "UNKNOWN"
    mapping: MappingVersion
    compliance_impact: Literal["UNCHANGED"] = "UNCHANGED"
    message: str


class MappingHistoryResponse(BaseModel):
    """Version history exposed to the local review UI."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    vendor: str
    versions: list[MappingVersion] = Field(default_factory=list)


def utc_now() -> datetime:
    """Return an aware UTC timestamp for local mapping records."""

    return datetime.now(timezone.utc)


def pattern_signature(vendor: str, raw_pattern: str) -> str:
    """Create a stable, non-sensitive signature for mapping lineage."""

    material = f"{vendor}:{raw_pattern.strip().lower()}".encode("utf-8")
    return sha256(material).hexdigest()
