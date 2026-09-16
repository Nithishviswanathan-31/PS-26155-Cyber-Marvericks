from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..domain.enums import ComplianceResult
from ..domain.remediation import RemediationDefinition, SimulatedChange
from ..domain.schemas import AnalysisResponse
from ..domain.security_ir import SecurityIR, SimulationProvenance


class RemediationError(ValueError):
    """Raised when a remediation is unavailable or unsafe to simulate."""


@dataclass(frozen=True)
class SimulationApplication:
    security_ir: SecurityIR
    changes: list[SimulatedChange]


_REMEDIATIONS: dict[tuple[str, str], RemediationDefinition] = {
    ("cisco_iosxe", "CTRL-001"): RemediationDefinition(
        remediation_id="REM-CTRL-001-CISCO",
        control_id="CTRL-001",
        vendor="cisco_iosxe",
        title="Enable SSH and disable Telnet",
        description="Review the VTY access list and restrict management transport to SSH only.",
        commands=["line vty 0 4", "transport input ssh"],
        target_properties=["management.ssh_enabled", "management.telnet_enabled"],
        expected_state={
            "management.ssh_enabled": True,
            "management.telnet_enabled": False,
        },
        risk_level="MEDIUM",
    ),
    ("fortigate_fortios", "CTRL-001"): RemediationDefinition(
        remediation_id="REM-CTRL-001-FORTIGATE",
        control_id="CTRL-001",
        vendor="fortigate_fortios",
        title="Restrict administrative access to SSH",
        description="Review the management interface and retain only approved secure access protocols.",
        commands=[
            "config system interface",
            "edit <reviewed-management-interface>",
            "set allowaccess <approved-access> ssh",
            "next",
            "end",
        ],
        target_properties=["management.ssh_enabled", "management.telnet_enabled"],
        expected_state={
            "management.ssh_enabled": True,
            "management.telnet_enabled": False,
        },
        risk_level="MEDIUM",
    ),
    ("paloalto_panos", "CTRL-001"): RemediationDefinition(
        remediation_id="REM-CTRL-001-PALOALTO",
        control_id="CTRL-001",
        vendor="paloalto_panos",
        title="Restrict the management profile to SSH",
        description="Review the assigned interface-management profile and allow SSH while disabling Telnet.",
        commands=[
            "set network profiles interface-management-profile <reviewed-profile> ssh yes",
            "set network profiles interface-management-profile <reviewed-profile> telnet no",
        ],
        target_properties=["management.ssh_enabled", "management.telnet_enabled"],
        expected_state={
            "management.ssh_enabled": True,
            "management.telnet_enabled": False,
        },
        risk_level="MEDIUM",
    ),
}

# These transformations change only parser-supported boolean properties on a
# deep-copied Security IR. Commands are advisory display text, never executed.
for _vendor, _prefix in (("cisco_iosxe", "CISCO"), ("fortigate_fortios", "FORTIGATE"), ("paloalto_panos", "PALOALTO")):
    _REMEDIATIONS[(_vendor, "CTRL-002")] = RemediationDefinition(
        remediation_id=f"REM-CTRL-002-{_prefix}", control_id="CTRL-002", vendor=_vendor,
        title="Enable audit logging", description="Simulate enabling the parser-supported audit logging state.",
        commands=["Review and enable the approved audit logging configuration."], target_properties=["logging.enabled"], expected_state={"logging.enabled": True}, risk_level="LOW")
    _REMEDIATIONS[(_vendor, "CTRL-003")] = RemediationDefinition(
        remediation_id=f"REM-CTRL-003-{_prefix}", control_id="CTRL-003", vendor=_vendor,
        title="Enable credential protection", description="Simulate enabling the parser-supported credential-protection state.",
        commands=["Review and enable the approved credential protection mechanism."], target_properties=["password_protection.enabled"], expected_state={"password_protection.enabled": True}, risk_level="HIGH")
    _REMEDIATIONS[(_vendor, "CTRL-004")] = RemediationDefinition(
        remediation_id=f"REM-CTRL-004-{_prefix}", control_id="CTRL-004", vendor=_vendor,
        title="Enable time synchronization", description="Simulate enabling the parser-supported NTP state.",
        commands=["Review and enable approved time synchronization."], target_properties=["time_sync.ntp_enabled"], expected_state={"time_sync.ntp_enabled": True}, risk_level="MEDIUM")


def list_remediation_capabilities(vendor: str | None = None, control_id: str | None = None) -> list[RemediationDefinition]:
    return [item for (item_vendor, item_control), item in _REMEDIATIONS.items() if (vendor is None or vendor == item_vendor) and (control_id is None or control_id == item_control)]


def validate_remediation_reference(vendor: str, control_id: str, reference: str) -> bool:
    definition = _REMEDIATIONS.get((vendor, control_id))
    return definition is not None and definition.remediation_id == reference


def get_remediations_for_analysis(analysis: AnalysisResponse) -> list[RemediationDefinition]:
    """Return reviewed recommendations only for explicit FAIL findings."""

    return [
        definition
        for result in analysis.results
        if result.result is ComplianceResult.FAIL
        for definition in [_REMEDIATIONS.get((analysis.vendor, result.control_id))]
        if definition is not None
    ]


def get_remediation(analysis: AnalysisResponse, remediation_id: str) -> RemediationDefinition:
    for remediation in get_remediations_for_analysis(analysis):
        if remediation.remediation_id == remediation_id:
            return remediation
    raise RemediationError("The requested remediation is unavailable for this analysis.")


def apply_simulation(
    security_ir: SecurityIR,
    remediation: RemediationDefinition,
    *,
    simulation_id: str,
    original_analysis_id: str,
) -> SimulationApplication:
    """Apply a reviewed transformation to a deep copy; never execute commands."""

    if remediation.simulation_only is not True:
        raise RemediationError("Only simulation-only remediations may be applied.")
    if set(remediation.target_properties) != set(remediation.expected_state):
        raise RemediationError("The remediation target and expected-state properties do not match.")

    enriched = security_ir.model_copy(deep=True)
    changes: list[SimulatedChange] = []
    for property_name in remediation.target_properties:
        trace = security_ir.trace_property(property_name)
        if trace is None or trace.provenance is None:
            raise RemediationError(f"No configuration provenance exists for '{property_name}'.")
        if property_name in security_ir.simulation_provenance:
            raise RemediationError(f"'{property_name}' is already simulated in this Security IR.")

        after_value = remediation.expected_state[property_name]
        changes.append(
            SimulatedChange(
                property=property_name,
                before_value=trace.value,
                after_value=after_value,
            )
        )
        enriched.normalized_properties[property_name] = after_value
        enriched.simulation_provenance[property_name] = SimulationProvenance(
            simulation_id=simulation_id,
            remediation_id=remediation.remediation_id,
            original_analysis_id=original_analysis_id,
            original_value=trace.value,
            simulated_value=after_value,
            original_location=trace.provenance,
        )

    return SimulationApplication(security_ir=enriched, changes=changes)


def simulation_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
