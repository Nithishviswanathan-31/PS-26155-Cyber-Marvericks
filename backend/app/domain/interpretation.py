from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

InterpretationStatus = Literal["PROPOSED", "NEEDS_REVIEW", "APPROVED", "REJECTED", "EXPIRED"]
ReviewAction = Literal["APPROVE", "CORRECT", "REJECT"]


class AIProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(min_length=1)
    analysis_id: str = Field(min_length=1)
    pattern_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    pattern_signature: str = Field(min_length=1)
    source_context: str = Field(min_length=1)
    candidate_property: str = Field(min_length=1)
    candidate_value: StrictBool
    candidate_mapping: dict[str, StrictBool] = Field(min_length=1)
    related_approved_mapping_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(min_length=1)
    interpreter_id: str = Field(min_length=1)
    interpreter_version: str = Field(min_length=1)
    status: InterpretationStatus = "NEEDS_REVIEW"
    created_at: datetime
    updated_at: datetime

    @field_validator("source_context", "explanation", "interpreter_id", "interpreter_version")
    @classmethod
    def nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("interpretation text cannot be blank")
        return value


class InterpretationReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer_id: str = Field(min_length=1)
    action: ReviewAction
    corrected_mapping: dict[str, StrictBool] | None = None
    reason: str | None = None

    @field_validator("reviewer_id")
    @classmethod
    def reviewer_nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reviewer_id cannot be blank")
        return value


class InterpretationEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    action: str
    reviewer_id: str | None = None
    mapping: dict[str, StrictBool] | None = None
    reason: str | None = None
    created_at: datetime


class InterpretationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    proposals: list[AIProposal] = Field(default_factory=list)


class InterpretationGenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern_id: str | None = None


class InterpretationReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal: AIProposal
    events: list[InterpretationEvent] = Field(default_factory=list)
    mapping_id: str | None = None
    mapping_version: int | None = None
    compliance_impact: Literal["UNCHANGED"] = "UNCHANGED"
