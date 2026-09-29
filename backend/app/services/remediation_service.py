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
    # -------------------------------------------------------------------------
    # CTRL-001: Secure management transport (SSH enabled, Telnet disabled)
    # -------------------------------------------------------------------------
    ("cisco_iosxe", "CTRL-001"): RemediationDefinition(
        remediation_id="REM-CTRL-001-CISCO",
        control_id="CTRL-001",
        vendor="cisco_iosxe",
        platform="Cisco IOS / IOS-XE",
        title="Enable SSH and disable Telnet",
        finding="Management access exposes unencrypted Telnet transport or lacks mandatory SSH encryption on VTY lines.",
        description="Review the VTY line access configuration and restrict remote terminal management transport to SSH only.",
        explanation="Enforces encrypted SSH transport on all virtual terminal lines (vty 0 4) and prevents cleartext transmission of credentials and session data by prohibiting Telnet.",
        applicability_notes="Applicable to Cisco IOS 12.x/15.x and IOS-XE 16.x/17.x. Assumes crypto host keys ('crypto key generate rsa') and domain name ('ip domain-name') are generated before restricting transport to prevent administrator lockout. For platforms with 16+ lines, adjust range to 'line vty 0 15'.",
        remediation_steps=[
            "Step 1: Enter global configuration mode: configure terminal",
            "Step 2: Enter VTY line configuration: line vty 0 4",
            "Step 3: Restrict inbound transport to SSH: transport input ssh",
            "Step 4: Return to privileged EXEC mode: end",
            "Step 5: Save running configuration to startup configuration: write memory",
        ],
        commands=[
            "configure terminal",
            "line vty 0 4",
            "transport input ssh",
            "end",
            "write memory",
        ],
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
        platform="FortiGate / FortiOS",
        title="Restrict administrative access to SSH",
        finding="Administrative interface permits insecure management protocols or lacks required SSH encapsulation.",
        description="Review the management interface configuration and retain only approved secure access protocols.",
        explanation="Modifies interface administrative access to enforce encrypted SSH and HTTPS while revoking unencrypted Telnet or HTTP access protocols.",
        applicability_notes="Applicable to FortiOS 6.0 through 7.4+. Parameter '<management-interface>' must be replaced with the actual administrative interface (e.g., 'mgmt' or 'port1'). Note: 'set allowaccess' replaces the existing access list; administrators must include any additional required management protocols (e.g., snmp, fgfm, fabric) to prevent accidental service loss.",
        remediation_steps=[
            "Step 1: Enter system interface configuration: config system interface",
            "Step 2: Select the target administrative management interface: edit <management-interface>",
            "Step 3: Restrict allowaccess to secure management protocols: set allowaccess ping https ssh",
            "Step 4: Save interface changes: next",
            "Step 5: Commit and exit configuration: end",
        ],
        commands=[
            "config system interface",
            "edit <management-interface>",
            "set allowaccess ping https ssh",
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
        platform="Palo Alto / PAN-OS",
        title="Restrict the management profile to SSH",
        finding="Interface management profile does not restrict access to SSH or permits insecure Telnet management.",
        description="Review the assigned interface-management profile and allow SSH while disabling Telnet.",
        explanation="Configures the network interface management profile to permit encrypted SSH administration and prohibit unencrypted Telnet sessions.",
        applicability_notes="Applicable to PAN-OS 8.1 through 11.x in-band Layer 3 interfaces. Parameter '<profile-name>' must be replaced with the active interface management profile name. For dedicated out-of-band management ('mgmt' interface), service restriction is configured globally under 'set deviceconfig system service disable-telnet yes' rather than via interface management profiles.",
        remediation_steps=[
            "Step 1: Enable SSH on the interface management profile: set network profiles interface-management-profile <profile-name> ssh yes",
            "Step 2: Disable unencrypted Telnet on the interface management profile: set network profiles interface-management-profile <profile-name> telnet no",
            "Step 3: Commit candidate configuration to active running system: commit",
        ],
        commands=[
            "set network profiles interface-management-profile <profile-name> ssh yes",
            "set network profiles interface-management-profile <profile-name> telnet no",
            "commit",
        ],
        target_properties=["management.ssh_enabled", "management.telnet_enabled"],
        expected_state={
            "management.ssh_enabled": True,
            "management.telnet_enabled": False,
        },
        risk_level="MEDIUM",
    ),

    # -------------------------------------------------------------------------
    # CTRL-002: Audit logging enabled
    # -------------------------------------------------------------------------
    ("cisco_iosxe", "CTRL-002"): RemediationDefinition(
        remediation_id="REM-CTRL-002-CISCO",
        control_id="CTRL-002",
        vendor="cisco_iosxe",
        platform="Cisco IOS / IOS-XE",
        title="Enable circular buffered logging",
        finding="Audit logging is disabled or circular buffer event logging is unconfigured in Cisco IOS-XE.",
        description="Configure circular memory-buffered logging to record security and operational events for audit traceability.",
        explanation="Enforces circular memory-buffered logging (64KB allocation) to capture security events, administrative commands, and system messages for local triage and forensic audit.",
        applicability_notes="Universally applicable to Cisco IOS 12.x/15.x and IOS-XE 16.x/17.x. Buffer size of 64000 bytes is suitable for standard memory configurations; adjust buffer allocation on memory-constrained platforms.",
        remediation_steps=[
            "Step 1: Enter global configuration mode: configure terminal",
            "Step 2: Enable circular buffer logging with 64KB memory allocation: logging buffered 64000",
            "Step 3: Set logging severity filter to capture informational and higher events: logging trap informational",
            "Step 4: Return to privileged EXEC mode: end",
            "Step 5: Save running configuration to NVRAM: write memory",
        ],
        commands=[
            "configure terminal",
            "logging buffered 64000",
            "logging trap informational",
            "end",
            "write memory",
        ],
        target_properties=["logging.enabled"],
        expected_state={"logging.enabled": True},
        risk_level="LOW",
    ),
    ("fortigate_fortios", "CTRL-002"): RemediationDefinition(
        remediation_id="REM-CTRL-002-FORTIGATE",
        control_id="CTRL-002",
        vendor="fortigate_fortios",
        platform="FortiGate / FortiOS",
        title="Enable persistent disk logging",
        finding="FortiOS local disk event logging is disabled, leaving administrative and policy events unrecorded.",
        description="Enable local disk log storage in FortiOS to maintain a persistent audit trail of security events.",
        explanation="Enforces disk log recording in FortiOS to maintain a persistent audit trail of security policy violations, administrator actions, and system events.",
        applicability_notes="Applicable only to FortiGate models equipped with onboard local storage/SSD (e.g., models ending with '1' such as 61F, 101F, or VM with a logging disk). On diskless desktop models (e.g., 40F, 60F), local disk logging is unavailable; substitute with memory logging ('config log memory setting') or remote syslog/FortiAnalyzer forwarding.",
        remediation_steps=[
            "Step 1: Enter log disk setting configuration: config log disk setting",
            "Step 2: Enable disk logging status: set status enable",
            "Step 3: Commit and exit configuration: end",
        ],
        commands=[
            "config log disk setting",
            "set status enable",
            "end",
        ],
        target_properties=["logging.enabled"],
        expected_state={"logging.enabled": True},
        risk_level="LOW",
    ),
    ("paloalto_panos", "CTRL-002"): RemediationDefinition(
        remediation_id="REM-CTRL-002-PALOALTO",
        control_id="CTRL-002",
        vendor="paloalto_panos",
        platform="Palo Alto / PAN-OS",
        title="Enable system audit log forwarding",
        finding="System event logging and audit forwarding is unconfigured in PAN-OS log settings.",
        description="Configure PAN-OS system log settings to forward events to central management for audit compliance.",
        explanation="Configures PAN-OS system log settings to forward all administrative, authentication, and system events to Panorama or central syslog monitoring.",
        applicability_notes="Applicable to PAN-OS 8.1 through 11.x deployments forwarding system logs to Panorama. For standalone firewalls utilizing external syslog receivers without Panorama, substitute with a Syslog Server Profile: 'set shared log-settings system match-list <name> server <syslog-profile>'.",
        remediation_steps=[
            "Step 1: Configure system log forwarding to Panorama in the system match list: set shared log-settings system match-list send-to-panorama send-to-panorama yes",
            "Step 2: Commit candidate configuration to the active device configuration: commit",
        ],
        commands=[
            "set shared log-settings system match-list send-to-panorama send-to-panorama yes",
            "commit",
        ],
        target_properties=["logging.enabled"],
        expected_state={"logging.enabled": True},
        risk_level="LOW",
    ),

    # -------------------------------------------------------------------------
    # CTRL-003: Secret protection enabled
    # -------------------------------------------------------------------------
    ("cisco_iosxe", "CTRL-003"): RemediationDefinition(
        remediation_id="REM-CTRL-003-CISCO",
        control_id="CTRL-003",
        vendor="cisco_iosxe",
        platform="Cisco IOS / IOS-XE",
        title="Enable service password-encryption",
        finding="Authentication secrets, passwords, and preshared keys are stored in plaintext within the Cisco configuration.",
        description="Enable the Cisco IOS password encryption service to encrypt all plaintext passwords stored in configuration.",
        explanation="Activates the Cisco IOS password-encryption service, which automatically encrypts all plaintext passwords (type 7) stored in the running and startup configuration files.",
        applicability_notes="Universally applicable to all Cisco IOS and IOS-XE releases. 'service password-encryption' enables reversible Type-7 obfuscation for plaintext passwords stored in configuration. For privileged administrative access, 'enable secret <password>' (Type-8/Type-9 PBKDF2/scrypt hashing) should be utilized alongside this setting.",
        remediation_steps=[
            "Step 1: Enter global configuration mode: configure terminal",
            "Step 2: Enable platform password encryption service: service password-encryption",
            "Step 3: Return to privileged EXEC mode: end",
            "Step 4: Save running configuration to startup configuration: write memory",
        ],
        commands=[
            "configure terminal",
            "service password-encryption",
            "end",
            "write memory",
        ],
        target_properties=["password_protection.enabled"],
        expected_state={"password_protection.enabled": True},
        risk_level="HIGH",
    ),
    ("fortigate_fortios", "CTRL-003"): RemediationDefinition(
        remediation_id="REM-CTRL-003-FORTIGATE",
        control_id="CTRL-003",
        vendor="fortigate_fortios",
        platform="FortiGate / FortiOS",
        title="Enable system password policy",
        finding="Administrator password policy enforcement is disabled, allowing weak or vulnerable passwords.",
        description="Enable the FortiOS system password policy to enforce complexity and minimum length requirements.",
        explanation="Enforces the FortiOS password policy with strict complexity requirements (minimum 12 characters, uppercase, lowercase, numeric, and special character requirements) for all administrative accounts.",
        applicability_notes="Applicable to FortiOS 6.0 through 7.4+. In multi-VDOM environments, password policy must be configured globally under 'config global'. In FortiOS 7.2+, fine-grained password policies can also be applied per administrative profile under 'config system admin'.",
        remediation_steps=[
            "Step 1: Enter system password-policy configuration: config system password-policy",
            "Step 2: Enable password policy enforcement: set status enable",
            "Step 3: Enforce minimum password length of 12 characters: set minimum-length 12",
            "Step 4: Commit and exit configuration: end",
        ],
        commands=[
            "config system password-policy",
            "set status enable",
            "set minimum-length 12",
            "end",
        ],
        target_properties=["password_protection.enabled"],
        expected_state={"password_protection.enabled": True},
        risk_level="HIGH",
    ),
    ("paloalto_panos", "CTRL-003"): RemediationDefinition(
        remediation_id="REM-CTRL-003-PALOALTO",
        control_id="CTRL-003",
        vendor="paloalto_panos",
        platform="Palo Alto / PAN-OS",
        title="Enable management password complexity",
        finding="Password complexity enforcement or username exclusion restriction is disabled in PAN-OS management configuration.",
        description="Configure PAN-OS password complexity to enforce strong credential requirements and block username inclusion.",
        explanation="Enforces PAN-OS password complexity policy and blocks passwords containing the account username to protect administrator credentials against dictionary and guessing attacks.",
        applicability_notes="Applicable to PAN-OS 8.1 through 11.x. Enforces management administrator password complexity across all local administrative accounts. To mandate specific character distribution, additional parameters (such as 'minimum-length 12', 'minimum-uppercase-letters 1', 'minimum-numeric-letters 1') can be appended.",
        remediation_steps=[
            "Step 1: Block inclusion of account username within administrator passwords: set mgt-config password-complexity block-username-inclusion yes",
            "Step 2: Enable password complexity enforcement: set mgt-config password-complexity enabled yes",
            "Step 3: Commit candidate configuration to active system: commit",
        ],
        commands=[
            "set mgt-config password-complexity block-username-inclusion yes",
            "set mgt-config password-complexity enabled yes",
            "commit",
        ],
        target_properties=["password_protection.enabled"],
        expected_state={"password_protection.enabled": True},
        risk_level="HIGH",
    ),

    # -------------------------------------------------------------------------
    # CTRL-004: Time synchronization configured
    # -------------------------------------------------------------------------
    ("cisco_iosxe", "CTRL-004"): RemediationDefinition(
        remediation_id="REM-CTRL-004-CISCO",
        control_id="CTRL-004",
        vendor="cisco_iosxe",
        platform="Cisco IOS / IOS-XE",
        title="Configure authoritative NTP server",
        finding="Network Time Protocol (NTP) synchronization is unconfigured, risking clock drift and invalid log timelines.",
        description="Configure an authoritative NTP server address to synchronize system clocks for audit correlation.",
        explanation="Configures authoritative Network Time Protocol (NTP) time synchronization to ensure chronological correlation of logs and security events.",
        applicability_notes="Universally applicable to Cisco IOS 12.x/15.x and IOS-XE 16.x/17.x. Parameter '<ntp-server-ip>' must be replaced with a valid IPv4/IPv6 address of an authoritative internal or public NTP server. For secure deployments, NTP symmetric key authentication ('ntp authenticate') is recommended.",
        remediation_steps=[
            "Step 1: Enter global configuration mode: configure terminal",
            "Step 2: Define authoritative NTP time server address: ntp server <ntp-server-ip>",
            "Step 3: Return to privileged EXEC mode: end",
            "Step 4: Save running configuration to startup configuration: write memory",
        ],
        commands=[
            "configure terminal",
            "ntp server <ntp-server-ip>",
            "end",
            "write memory",
        ],
        target_properties=["time_sync.ntp_enabled"],
        expected_state={"time_sync.ntp_enabled": True},
        risk_level="MEDIUM",
    ),
    ("fortigate_fortios", "CTRL-004"): RemediationDefinition(
        remediation_id="REM-CTRL-004-FORTIGATE",
        control_id="CTRL-004",
        vendor="fortigate_fortios",
        platform="FortiGate / FortiOS",
        title="Enable NTP synchronization",
        finding="FortiOS NTP synchronization is disabled, resulting in unsynchronized clock timestamps across firewall event logs.",
        description="Enable NTP synchronization and configure an authoritative NTP server in FortiOS.",
        explanation="Enables NTP time synchronization in FortiOS and designates an authoritative custom NTP server for accurate event chronology.",
        applicability_notes="Applicable to FortiOS 6.0 through 7.4+. Parameter '<ntp-server-ip>' must be replaced with the authoritative NTP server IP address. In multi-VDOM environments, NTP configuration is a global system parameter and must be executed under 'config global'.",
        remediation_steps=[
            "Step 1: Enter system NTP configuration: config system ntp",
            "Step 2: Enable NTP synchronization: set ntpsync enable",
            "Step 3: Set NTP mode to custom: set type custom",
            "Step 4: Enter NTP server configuration: config ntpserver",
            "Step 5: Define NTP server entry 1: edit 1",
            "Step 6: Set authoritative NTP server IP address: set server \"<ntp-server-ip>\"",
            "Step 7: Save server entry: next",
            "Step 8: Exit NTP server list: end",
            "Step 9: Commit and exit configuration: end",
        ],
        commands=[
            "config system ntp",
            "set ntpsync enable",
            "set type custom",
            "config ntpserver",
            "edit 1",
            "set server \"<ntp-server-ip>\"",
            "next",
            "end",
            "end",
        ],
        target_properties=["time_sync.ntp_enabled"],
        expected_state={"time_sync.ntp_enabled": True},
        risk_level="MEDIUM",
    ),
    ("paloalto_panos", "CTRL-004"): RemediationDefinition(
        remediation_id="REM-CTRL-004-PALOALTO",
        control_id="CTRL-004",
        vendor="paloalto_panos",
        platform="Palo Alto / PAN-OS",
        title="Configure primary NTP server",
        finding="Primary NTP server address is unconfigured in PAN-OS system device configuration.",
        description="Configure the primary NTP server IP under PAN-OS system device configuration to ensure synchronized clock time.",
        explanation="Configures the primary NTP server IP under PAN-OS system deviceconfig to ensure synchronized clock time for security logs, reports, and certificate expiration checks.",
        applicability_notes="Applicable to PAN-OS 8.0 through 11.x. Parameter '<ntp-server-ip>' must be replaced with the authoritative NTP server IP address. To configure an optional secondary fallback NTP server, use 'set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address <secondary-ip>'.",
        remediation_steps=[
            "Step 1: Set primary NTP server address: set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <ntp-server-ip>",
            "Step 2: Commit candidate configuration to active system: commit",
        ],
        commands=[
            "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <ntp-server-ip>",
            "commit",
        ],
        target_properties=["time_sync.ntp_enabled"],
        expected_state={"time_sync.ntp_enabled": True},
        risk_level="MEDIUM",
    ),
}


def list_remediation_capabilities(vendor: str | None = None, control_id: str | None = None) -> list[RemediationDefinition]:
    return [item for (item_vendor, item_control), item in _REMEDIATIONS.items() if (vendor is None or vendor == item_vendor) and (control_id is None or control_id == item_control)]


def validate_remediation_reference(vendor: str, control_id: str, reference: str) -> bool:
    definition = _REMEDIATIONS.get((vendor, control_id))
    return definition is not None and definition.remediation_id == reference


def get_remediation_definition(remediation_id: str) -> RemediationDefinition | None:
    for definition in _REMEDIATIONS.values():
        if definition.remediation_id == remediation_id:
            return definition
    return None


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
