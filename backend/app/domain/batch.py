from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

BatchStatus = Literal["QUEUED", "PROCESSING", "COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"]
BatchItemStatus = Literal["QUEUED", "PROCESSING", "COMPLETED", "FAILED", "DUPLICATE"]


class BatchItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    batch_item_id: str
    source_filename: str
    configuration_id: str | None = None
    device_id: str | None = None
    analysis_id: str | None = None
    content_sha256: str | None = None
    processing_status: BatchItemStatus
    error_code: str | None = None
    error_message: str | None = None
    duplicate_of_configuration_id: str | None = None
    compliance_status: Literal["PASS", "FAIL", "UNKNOWN", "MIXED"] | None = None
    vendor: str | None = None
    platform: str | None = None
    hostname: str | None = None
    device_model: str | None = None
    serial_number: str | None = None
    pass_count: int = Field(default=0, ge=0)
    fail_count: int = Field(default=0, ge=0)
    unknown_count: int = Field(default=0, ge=0)
    not_applicable_count: int = Field(default=0, ge=0)
    created_at: datetime
    updated_at: datetime


class BatchSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0)
    processed: int = Field(ge=0)
    successful: int = Field(ge=0)
    failed: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    pass_analyses: int = Field(ge=0)
    fail_analyses: int = Field(ge=0)
    unknown_analyses: int = Field(ge=0)
    vendors_detected: list[str] = Field(default_factory=list)
    devices_analyzed: list[str] = Field(default_factory=list)
    pass_count: int = Field(default=0, ge=0)
    fail_count: int = Field(default=0, ge=0)
    unknown_count: int = Field(default=0, ge=0)
    not_applicable_count: int = Field(default=0, ge=0)


class BatchAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    batch_id: str
    submitted_at: datetime
    total_items: int = Field(ge=0)
    processed_items: int = Field(ge=0)
    successful_items: int = Field(ge=0)
    failed_items: int = Field(ge=0)
    duplicate_items: int = Field(ge=0)
    status: BatchStatus
    source: str = "UPLOAD"
    summary: BatchSummary

