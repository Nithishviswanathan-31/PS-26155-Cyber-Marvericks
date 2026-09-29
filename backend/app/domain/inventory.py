"""Local device observations and configuration upload events, separate from audits."""
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .security_ir import SourceLocation


class Device(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(min_length=1)
    hostname: str | None = None
    vendor: str = Field(min_length=1)
    platform: str | None = None
    software_version: str | None = None
    device_model: str | None = None
    serial_number: str | None = None
    configuration_source: Literal["UPLOAD"] = "UPLOAD"
    metadata: dict[str, Any] = Field(default_factory=dict)
    metadata_provenance: dict[str, SourceLocation] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    configuration_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    source_filename: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    detected_vendor: str = Field(min_length=1)
    detection_method: Literal["PARSER_SIGNATURE"] = "PARSER_SIGNATURE"
    source: Literal["UPLOAD"] = "UPLOAD"
    uploaded_at: datetime
    parser_status: Literal["PARSED", "PARTIAL"]
    duplicate_of_configuration_id: str | None = None
    created_at: datetime
    updated_at: datetime


class ConfigurationHistory(BaseModel):
    configuration: Configuration
    analysis_ids: list[str]


class DeviceAnalysisHistory(BaseModel):
    device_id: str
    analysis_ids: list[str]
