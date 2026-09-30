from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.domain.enums import ComplianceResult
from app.domain.remediation import RemediationDefinition, SimulatedChange, SimulationResponse
from app.domain.security_ir import DeviceInfo, PropertyTrace, SecurityIR, SimulationProvenance, SourceLocation
from app.main import app
from app.services.remediation_service import (
    apply_simulation,
    get_remediation_definition,
    list_remediation_capabilities,
    validate_remediation_reference,
)
from app.services.report_service import generate_analysis_pdf
from app.storage.database import get_connection, initialize_database


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def isolate_db() -> None:
    initialize_database()
    connection = get_connection()
    try:
        connection.execute("DELETE FROM simulation_results")
        connection.execute("DELETE FROM interpretation_events")
        connection.execute("DELETE FROM interpretation_proposals")
        connection.execute("DELETE FROM analysis_results")
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def upload(client: TestClient, vendor: str, filename: str) -> tuple[str, dict]:
    path = ROOT / "configs" / vendor / filename
    response = client.post(
        "/api/analyze",
        files={"file": (filename, path.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    return payload["analysis_id"], payload


# =============================================================================
# 1. Vendor-Specific Command Generation & Structured Format Tests
# =============================================================================

@pytest.mark.parametrize("vendor,platform_keyword", [
    ("cisco_iosxe", "Cisco"),
    ("fortigate_fortios", "FortiGate"),
    ("paloalto_panos", "Palo Alto"),
])
@pytest.mark.parametrize("control_id", [
    "CTRL-001",
    "CTRL-002",
    "CTRL-003",
    "CTRL-004",
])
def test_all_12_vendor_remediations_exist_and_are_structured(vendor: str, platform_keyword: str, control_id: str) -> None:
    remediations = list_remediation_capabilities(vendor=vendor, control_id=control_id)
    assert len(remediations) == 1, f"Expected exactly one remediation for {vendor} {control_id}"

    rem = remediations[0]
    assert rem.vendor == vendor
    assert rem.control_id == control_id
    assert platform_keyword in (rem.platform or "")
    assert rem.finding is not None and len(rem.finding) > 15
    assert rem.explanation is not None and len(rem.explanation) > 20
    assert rem.applicability_notes is not None and len(rem.applicability_notes) > 20

    # Verify structured steps
    assert len(rem.remediation_steps) >= 2, f"Expected at least 2 steps for {rem.remediation_id}"
    for step in rem.remediation_steps:
        assert step.startswith("Step "), f"Step must start with 'Step ': {step}"

    # Verify structured CLI commands (not one giant string or placeholder)
    assert len(rem.commands) >= 2, f"Expected multiple command strings for {rem.remediation_id}"
    for cmd in rem.commands:
        assert isinstance(cmd, str) and len(cmd.strip()) > 0
        assert "placeholder" not in cmd.lower()
        assert "TODO" not in cmd

    # Verify safety markers
    assert rem.simulation_only is True
    assert rem.safety_classification == "SIMULATION_ONLY"
    assert rem.simulation_capability == "DETERMINISTIC"
    assert rem.transformation_type == "SECURITY_IR_PROPERTY_SIMULATION"
    assert set(rem.target_properties) == set(rem.expected_state.keys())


def test_cisco_syntax_correctness() -> None:
    # CTRL-001: SSH & VTY
    cisco_001 = list_remediation_capabilities(vendor="cisco_iosxe", control_id="CTRL-001")[0]
    assert "line vty 0 4" in cisco_001.commands
    assert "transport input ssh" in cisco_001.commands

    # CTRL-002: Logging
    cisco_002 = list_remediation_capabilities(vendor="cisco_iosxe", control_id="CTRL-002")[0]
    assert any("logging buffered" in cmd for cmd in cisco_002.commands)
    assert any("logging trap" in cmd for cmd in cisco_002.commands)

    # CTRL-003: Password encryption
    cisco_003 = list_remediation_capabilities(vendor="cisco_iosxe", control_id="CTRL-003")[0]
    assert "service password-encryption" in cisco_003.commands

    # CTRL-004: NTP
    cisco_004 = list_remediation_capabilities(vendor="cisco_iosxe", control_id="CTRL-004")[0]
    assert any("ntp server" in cmd for cmd in cisco_004.commands)


def test_fortigate_syntax_correctness() -> None:
    # CTRL-001: Interface allowaccess
    fg_001 = list_remediation_capabilities(vendor="fortigate_fortios", control_id="CTRL-001")[0]
    assert "config system interface" in fg_001.commands
    assert any("set allowaccess" in cmd and "ssh" in cmd for cmd in fg_001.commands)

    # CTRL-002: Log disk setting
    fg_002 = list_remediation_capabilities(vendor="fortigate_fortios", control_id="CTRL-002")[0]
    assert "config log disk setting" in fg_002.commands
    assert "set status enable" in fg_002.commands

    # CTRL-003: Password policy
    fg_003 = list_remediation_capabilities(vendor="fortigate_fortios", control_id="CTRL-003")[0]
    assert "config system password-policy" in fg_003.commands
    assert "set status enable" in fg_003.commands
    assert any("minimum-length" in cmd for cmd in fg_003.commands)

    # CTRL-004: NTP
    fg_004 = list_remediation_capabilities(vendor="fortigate_fortios", control_id="CTRL-004")[0]
    assert "config system ntp" in fg_004.commands
    assert "set ntpsync enable" in fg_004.commands


def test_paloalto_syntax_correctness() -> None:
    # CTRL-001: Interface management profile
    pa_001 = list_remediation_capabilities(vendor="paloalto_panos", control_id="CTRL-001")[0]
    assert any("interface-management-profile" in cmd and "ssh yes" in cmd for cmd in pa_001.commands)
    assert any("interface-management-profile" in cmd and "telnet no" in cmd for cmd in pa_001.commands)

    # CTRL-002: Panorama logging
    pa_002 = list_remediation_capabilities(vendor="paloalto_panos", control_id="CTRL-002")[0]
    assert any("log-settings" in cmd and "send-to-panorama" in cmd for cmd in pa_002.commands)

    # CTRL-003: Password complexity
    pa_003 = list_remediation_capabilities(vendor="paloalto_panos", control_id="CTRL-003")[0]
    assert any("password-complexity" in cmd and "enabled yes" in cmd for cmd in pa_003.commands)

    # CTRL-004: NTP
    pa_004 = list_remediation_capabilities(vendor="paloalto_panos", control_id="CTRL-004")[0]
    assert any("ntp-servers" in cmd for cmd in pa_004.commands)


# =============================================================================
# 2. Diagnostic Child Controls Safety
# =============================================================================

def test_diagnostic_child_controls_have_no_separate_remediation() -> None:
    """CTRL-005 and CTRL-006 are child diagnostic checks of CTRL-001.
    They must never have separate broken/standalone remediations that risk admin lockout.
    """
    assert list_remediation_capabilities(control_id="CTRL-005") == []
    assert list_remediation_capabilities(control_id="CTRL-006") == []

    # The parent control CTRL-001 targets both properties together
    for vendor in ["cisco_iosxe", "fortigate_fortios", "paloalto_panos"]:
        rem = list_remediation_capabilities(vendor=vendor, control_id="CTRL-001")[0]
        assert "management.ssh_enabled" in rem.target_properties
        assert "management.telnet_enabled" in rem.target_properties
        assert rem.expected_state["management.ssh_enabled"] is True
        assert rem.expected_state["management.telnet_enabled"] is False


# =============================================================================
# 3. Simulation Safety & Invariants
# =============================================================================

def test_simulation_applies_to_deep_copy_and_preserves_original() -> None:
    original_ir = SecurityIR(
        device=DeviceInfo(vendor="cisco_iosxe", hostname="router-1"),
        normalized_properties={
            "management.ssh_enabled": False,
            "management.telnet_enabled": True,
        },
        provenance={
            "management.ssh_enabled": SourceLocation(source_file="test.conf", line_start=1, line_end=2, raw_excerpt="line vty 0 4"),
            "management.telnet_enabled": SourceLocation(source_file="test.conf", line_start=3, line_end=4, raw_excerpt="transport input telnet"),
        },
    )

    rem = list_remediation_capabilities(vendor="cisco_iosxe", control_id="CTRL-001")[0]
    sim_app = apply_simulation(
        original_ir,
        rem,
        simulation_id="SIM-123",
        original_analysis_id="ANA-123",
    )

    # 1. Original IR is untouched
    assert original_ir.normalized_properties["management.ssh_enabled"] is False
    assert original_ir.normalized_properties["management.telnet_enabled"] is True
    assert original_ir.simulation_provenance == {}

    # 2. Simulated IR has modified properties
    assert sim_app.security_ir.normalized_properties["management.ssh_enabled"] is True
    assert sim_app.security_ir.normalized_properties["management.telnet_enabled"] is False

    # 3. Simulation provenance attached
    assert "management.ssh_enabled" in sim_app.security_ir.simulation_provenance
    assert "management.telnet_enabled" in sim_app.security_ir.simulation_provenance
    prov = sim_app.security_ir.simulation_provenance["management.ssh_enabled"]
    assert prov.simulation_id == "SIM-123"
    assert prov.original_value is False
    assert prov.simulated_value is True

    # 4. Changes recorded with SIMULATED_REMEDIATION
    assert len(sim_app.changes) == 2
    for change in sim_app.changes:
        assert change.change_source == "SIMULATED_REMEDIATION"


def test_unsafe_remediation_definition_rejected_by_model() -> None:
    with pytest.raises(ValidationError):
        RemediationDefinition.model_validate({
            "remediation_id": "REM-UNSAFE",
            "control_id": "CTRL-001",
            "vendor": "cisco_iosxe",
            "title": "Unsafe Real Execution",
            "description": "Attempting live execution",
            "commands": ["reload"],
            "target_properties": ["management.ssh_enabled"],
            "expected_state": {"management.ssh_enabled": True},
            "risk_level": "HIGH",
            "simulation_only": False,  # MUST FAIL validation
        })


# =============================================================================
# 4. API Endpoints & Capabilities Filtering
# =============================================================================

def test_capabilities_api_returns_enriched_metadata(client: TestClient) -> None:
    response = client.get("/api/remediation/capabilities?vendor=cisco_iosxe&control_id=CTRL-001")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    rem = items[0]
    assert rem["platform"] == "Cisco IOS / IOS-XE"
    assert "Finding" in rem or rem.get("finding") is not None
    assert "explanation" in rem and rem["explanation"] is not None
    assert len(rem["remediation_steps"]) >= 4
    assert len(rem["commands"]) >= 4
    assert rem["simulation_only"] is True


def test_get_remediation_definition_helper() -> None:
    definition = get_remediation_definition("REM-CTRL-001-CISCO")
    assert definition is not None
    assert definition.vendor == "cisco_iosxe"
    assert definition.control_id == "CTRL-001"

    missing = get_remediation_definition("REM-NONEXISTENT")
    assert missing is None


# =============================================================================
# 5. Multi-Vendor End-to-End Simulation & PDF Report Generation
# =============================================================================

@pytest.mark.parametrize("vendor,filename,expected_remediation_id", [
    ("cisco", "noncompliant.conf", "REM-CTRL-001-CISCO"),
    ("fortigate", "noncompliant.conf", "REM-CTRL-001-FORTIGATE"),
    ("paloalto", "noncompliant.conf", "REM-CTRL-001-PALOALTO"),
])
def test_end_to_end_simulation_and_pdf_generation(
    client: TestClient,
    vendor: str,
    filename: str,
    expected_remediation_id: str,
) -> None:
    analysis_id, analysis_payload = upload(client, vendor, filename)
    remediations_resp = client.get(f"/api/remediation/{analysis_id}")
    assert remediations_resp.status_code == 200
    remediations = remediations_resp.json()["remediations"]
    assert any(r["remediation_id"] == expected_remediation_id for r in remediations)

    # Perform simulation
    sim_resp = client.post(
        f"/api/remediation/{analysis_id}/simulate",
        json={"remediation_id": expected_remediation_id},
    )
    assert sim_resp.status_code == 200
    sim_payload = sim_resp.json()
    assert sim_payload["before_result"] == "FAIL"
    assert sim_payload["after_result"] == "PASS"
    assert sim_payload["simulation_only"] is True

    # Test PDF generation for analysis with simulation results
    pdf_resp = client.get(f"/api/reports/{analysis_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF")
    assert len(pdf_resp.content) > 1000
