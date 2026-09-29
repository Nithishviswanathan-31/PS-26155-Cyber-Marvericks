"""Compliance framework registry and metadata definitions.

Framework references are advisory cross-references only. They do not
participate in deterministic PASS / FAIL / UNKNOWN compliance evaluation.
"""
from typing import Literal
from pydantic import BaseModel, ConfigDict

FrameworkId = Literal["CIS", "NIST_SP_800_53", "DISA_STIG", "ISO_27001"]
FrameworkVerificationStatus = Literal["SUPPORTED", "PROTOTYPE"]


class FrameworkInfo(BaseModel):
    """Metadata describing a supported security compliance framework."""

    model_config = ConfigDict(extra="forbid")

    framework_id: FrameworkId
    display_name: str
    version: str
    description: str
    verification_status: FrameworkVerificationStatus = "SUPPORTED"
    authoritative_url: str | None = None


FRAMEWORK_REGISTRY: dict[FrameworkId, FrameworkInfo] = {
    "CIS": FrameworkInfo(
        framework_id="CIS",
        display_name="CIS Critical Security Controls",
        version="v8",
        description="Prescriptive, prioritized set of cybersecurity best practices published by the Center for Internet Security.",
        verification_status="SUPPORTED",
        authoritative_url="https://www.cisecurity.org/controls/cis-controls-list",
    ),
    "NIST_SP_800_53": FrameworkInfo(
        framework_id="NIST_SP_800_53",
        display_name="NIST SP 800-53",
        version="Rev. 5",
        description="Security and Privacy Controls for Information Systems and Organizations published by NIST.",
        verification_status="SUPPORTED",
        authoritative_url="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "DISA_STIG": FrameworkInfo(
        framework_id="DISA_STIG",
        display_name="DISA STIG",
        version="Network Device STIG",
        description="Department of Defense / DISA Security Technical Implementation Guides for network devices. Cross-references are prototype/internal mappings.",
        verification_status="PROTOTYPE",
        authoritative_url="https://public.cyber.mil/stigs/",
    ),
    "ISO_27001": FrameworkInfo(
        framework_id="ISO_27001",
        display_name="ISO/IEC 27001",
        version="2022",
        description="International standard for Information Security Management Systems (ISMS), Annex A information security controls.",
        verification_status="SUPPORTED",
        authoritative_url="https://www.iso.org/standard/27001",
    ),
}


def get_framework_registry() -> list[FrameworkInfo]:
    """Return all supported compliance frameworks."""
    return list(FRAMEWORK_REGISTRY.values())


def get_framework_info(framework_id: str) -> FrameworkInfo | None:
    """Lookup framework metadata by ID."""
    return FRAMEWORK_REGISTRY.get(framework_id)  # type: ignore[arg-type]
