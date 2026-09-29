from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.parsers.cisco import CiscoParser
from app.parsers.fortigate import FortiGateParser
from app.parsers.paloalto import PaloAltoParser
from app.services.report_service import generate_analysis_pdf
from app.storage.database import reset_demo_database

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client():
    reset_demo_database()
    with TestClient(app) as value:
        yield value
    reset_demo_database()


# =========================================================================
# Cisco IOS / IOS-XE Device Identification Tests
# =========================================================================

def test_cisco_device_id_extraction_from_license_udi():
    config = """version 17.9
hostname core-router-01
license udi pid C9300-48P sn FCW2140A0AB
logging buffered 64000
line vty 0 4
 transport input ssh
!
"""
    ir = CiscoParser.parse(config, source_file="cisco_test.conf")
    assert ir.device.vendor == "cisco_iosxe"
    assert ir.device.hostname == "core-router-01"
    assert ir.device.version == "17.9"
    assert ir.device.device_model == "C9300-48P"
    assert ir.device.serial_number == "FCW2140A0AB"

    # Provenance verification
    model_prov = ir.device.metadata_provenance.get("device_model")
    assert model_prov is not None
    assert model_prov.line_start == 3
    assert model_prov.line_end == 3
    assert "license udi pid C9300-48P sn FCW2140A0AB" in model_prov.raw_excerpt

    serial_prov = ir.device.metadata_provenance.get("serial_number")
    assert serial_prov is not None
    assert serial_prov.line_start == 3
    assert serial_prov.line_end == 3
    assert "FCW2140A0AB" in serial_prov.raw_excerpt


def test_cisco_device_id_extraction_from_comments():
    config = """! Chassis: ISR4431/K9
! Serial Number: FGL193820ZZ
! Platform: Cisco-ISR4400
version 17.9
hostname edge-router-01
logging buffered 64000
line vty 0 4
 transport input ssh
!
"""
    ir = CiscoParser.parse(config, source_file="cisco_comments.conf")
    assert ir.device.device_model == "ISR4431/K9"
    assert ir.device.serial_number == "FGL193820ZZ"
    assert ir.device.platform == "Cisco-ISR4400"
    assert ir.device.metadata_provenance["device_model"].line_start == 1
    assert ir.device.metadata_provenance["serial_number"].line_start == 2
    assert ir.device.metadata_provenance["platform"].line_start == 3


def test_cisco_device_id_extraction_processor_board_id():
    config = """! Processor board ID: FOC18280Z2K
! PID: WS-C3850-24T
version 16.12
hostname switch-access-01
logging buffered 64000
line vty 0 4
 transport input ssh
!
"""
    ir = CiscoParser.parse(config, source_file="cisco_board.conf")
    assert ir.device.device_model == "WS-C3850-24T"
    assert ir.device.serial_number == "FOC18280Z2K"


def test_cisco_device_id_absent_remains_null():
    config = """version 17.9
hostname demo-cisco-compliant
service password-encryption
logging buffered 64000
ntp server 192.0.2.10
line vty 0 4
 transport input ssh
!
"""
    ir = CiscoParser.parse(config, source_file="compliant.conf")
    assert ir.device.hostname == "demo-cisco-compliant"
    assert ir.device.version == "17.9"
    assert ir.device.device_model is None
    assert ir.device.serial_number is None
    assert ir.device.platform is None
    assert "device_model" not in ir.device.metadata_provenance
    assert "serial_number" not in ir.device.metadata_provenance
    assert "platform" not in ir.device.metadata_provenance


def test_cisco_fixture_file_extraction():
    fixture_path = ROOT / "configs" / "fixtures" / "cisco_with_device_id.conf"
    ir = CiscoParser.parse(fixture_path.read_text(encoding="utf-8"), source_file="cisco_with_device_id.conf")
    assert ir.device.vendor == "cisco_iosxe"
    assert ir.device.hostname == "edge-router-01"
    assert ir.device.version == "17.9"
    assert ir.device.device_model == "ISR4431/K9"
    assert ir.device.serial_number == "FGL193820ZZ"
    assert ir.device.platform == "Cisco-ISR4400"


# =========================================================================
# FortiGate / FortiOS Device Identification Tests
# =========================================================================

def test_fortigate_device_id_extraction_from_headers():
    config = """#config-version=FGT60F v7.4.3,build2573
#serial_number=FGT60FTK20000001
# Model: FortiGate-60F
config system global
    set hostname "branch-fw-01"
end
"""
    ir = FortiGateParser.parse(config, source_file="fg_header.conf")
    assert ir.device.vendor == "fortigate_fortios"
    assert ir.device.hostname == "branch-fw-01"
    assert ir.device.version == "7.4.3"
    assert ir.device.platform == "FGT60F"
    assert ir.device.device_model == "FortiGate-60F"
    assert ir.device.serial_number == "FGT60FTK20000001"

    # Provenance verification
    serial_prov = ir.device.metadata_provenance.get("serial_number")
    assert serial_prov is not None
    assert serial_prov.line_start == 2
    assert "FGT60FTK20000001" in serial_prov.raw_excerpt

    model_prov = ir.device.metadata_provenance.get("device_model")
    assert model_prov is not None
    assert model_prov.line_start == 3
    assert "FortiGate-60F" in model_prov.raw_excerpt


def test_fortigate_device_id_extraction_from_system_global():
    config = """#config-version=FGT100E v7.2.4,build1396
config system global
    set hostname "core-fw-01"
    set model "FortiGate-100E"
    set serial-number "FGT100ETK18000042"
end
"""
    ir = FortiGateParser.parse(config, source_file="fg_global.conf")
    assert ir.device.device_model == "FortiGate-100E"
    assert ir.device.serial_number == "FGT100ETK18000042"
    assert ir.device.metadata_provenance["device_model"].line_start == 4
    assert ir.device.metadata_provenance["serial_number"].line_start == 5


def test_fortigate_device_id_fallback_to_config_version():
    config = """#config-version=FGT60F v7.4.3,build2573
config system global
    set hostname "demo-fortigate-compliant"
end
"""
    ir = FortiGateParser.parse(config, source_file="fg_fallback.conf")
    assert ir.device.platform == "FGT60F"
    assert ir.device.device_model == "FGT60F"
    assert ir.device.serial_number is None
    assert "serial_number" not in ir.device.metadata_provenance


def test_fortigate_fixture_file_extraction():
    fixture_path = ROOT / "configs" / "fixtures" / "fortigate_with_device_id.conf"
    ir = FortiGateParser.parse(fixture_path.read_text(encoding="utf-8"), source_file="fortigate_with_device_id.conf")
    assert ir.device.vendor == "fortigate_fortios"
    assert ir.device.hostname == "branch-firewall-01"
    assert ir.device.version == "7.4.3"
    assert ir.device.platform == "FGT60F"
    assert ir.device.device_model == "FortiGate-60F"
    assert ir.device.serial_number == "FGT60FTK20000001"


# =========================================================================
# Palo Alto / PAN-OS Device Identification Tests
# =========================================================================

def test_paloalto_device_id_extraction_from_comments():
    config = """# Model: PA-3220
# Serial Number: 012345678901
# Version: 10.2.3
# Platform: PA-3200
set deviceconfig system hostname pa-gateway-01
set network profiles interface-management-profile mgmt-profile ssh yes
"""
    ir = PaloAltoParser.parse(config, source_file="pa_comments.conf")
    assert ir.device.vendor == "paloalto_panos"
    assert ir.device.hostname == "pa-gateway-01"
    assert ir.device.version == "10.2.3"
    assert ir.device.platform == "PA-3200"
    assert ir.device.device_model == "PA-3220"
    assert ir.device.serial_number == "012345678901"

    # Provenance verification
    model_prov = ir.device.metadata_provenance.get("device_model")
    assert model_prov is not None
    assert model_prov.line_start == 1
    assert "PA-3220" in model_prov.raw_excerpt

    serial_prov = ir.device.metadata_provenance.get("serial_number")
    assert serial_prov is not None
    assert serial_prov.line_start == 2
    assert "012345678901" in serial_prov.raw_excerpt


def test_paloalto_device_id_extraction_from_set_commands():
    config = """set deviceconfig system hostname pa-perimeter-01
set deviceconfig system model PA-5250
set deviceconfig system serial 001122334455
set deviceconfig system version 11.0.1
set deviceconfig system platform PA-5200
set network profiles interface-management-profile mgmt-profile ssh yes
"""
    ir = PaloAltoParser.parse(config, source_file="pa_set.conf")
    assert ir.device.hostname == "pa-perimeter-01"
    assert ir.device.device_model == "PA-5250"
    assert ir.device.serial_number == "001122334455"
    assert ir.device.version == "11.0.1"
    assert ir.device.platform == "PA-5200"
    assert ir.device.metadata_provenance["device_model"].line_start == 2
    assert ir.device.metadata_provenance["serial_number"].line_start == 3


def test_paloalto_device_id_absent_remains_null():
    config = """set deviceconfig system hostname pa-datacenter-gw
set network profiles interface-management-profile mgmt-profile ssh yes
set network profiles interface-management-profile mgmt-profile telnet no
set network interface ethernet1/1 interface-management-profile mgmt-profile
set shared log-settings system match-list send-to-panorama yes
set mgt-config password-complexity block-username-inclusion yes
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 192.0.2.10
"""
    ir = PaloAltoParser.parse(config, source_file="pa_compliant.conf")
    assert ir.device.hostname == "pa-datacenter-gw"
    assert ir.device.device_model is None
    assert ir.device.serial_number is None
    assert ir.device.version is None
    assert ir.device.platform is None
    assert "device_model" not in ir.device.metadata_provenance
    assert "serial_number" not in ir.device.metadata_provenance


def test_paloalto_fixture_file_extraction():
    fixture_path = ROOT / "configs" / "fixtures" / "paloalto_with_device_id.conf"
    ir = PaloAltoParser.parse(fixture_path.read_text(encoding="utf-8"), source_file="paloalto_with_device_id.conf")
    assert ir.device.vendor == "paloalto_panos"
    assert ir.device.hostname == "pa-gateway-01"
    assert ir.device.version == "10.2.3"
    assert ir.device.platform == "PA-3200"
    assert ir.device.device_model == "PA-3220"
    assert ir.device.serial_number == "012345678901"


# =========================================================================
# End-to-End API and Inventory Verification
# =========================================================================

def test_api_upload_persists_and_exposes_device_identification(client):
    fixture_path = ROOT / "configs" / "fixtures" / "cisco_with_device_id.conf"
    response = client.post(
        "/api/analyze",
        files={"file": ("cisco_with_device_id.conf", fixture_path.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    analysis = response.json()

    # Analysis response contains device identification
    device_info = analysis["device"]
    assert device_info["hostname"] == "edge-router-01"
    assert device_info["version"] == "17.9"
    assert device_info["device_model"] == "ISR4431/K9"
    assert device_info["serial_number"] == "FGL193820ZZ"
    assert device_info["platform"] == "Cisco-ISR4400"
    assert device_info["device_id"] is not None

    # GET /api/devices/{device_id} returns matching device inventory record
    device_record = client.get(f"/api/devices/{device_info['device_id']}").json()
    assert device_record["device_id"] == device_info["device_id"]
    assert device_record["hostname"] == "edge-router-01"
    assert device_record["vendor"] == "cisco_iosxe"
    assert device_record["platform"] == "Cisco-ISR4400"
    assert device_record["software_version"] == "17.9"
    assert device_record["device_model"] == "ISR4431/K9"
    assert device_record["serial_number"] == "FGL193820ZZ"


def test_api_upload_with_absent_metadata_preserves_null(client):
    response = client.post(
        "/api/analyze",
        files={"file": ("compliant.conf", (ROOT / "configs" / "cisco" / "compliant.conf").read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    analysis = response.json()
    assert analysis["device"]["hostname"] == "demo-cisco-compliant"
    assert analysis["device"]["version"] == "17.9"
    assert analysis["device"]["device_model"] is None
    assert analysis["device"]["serial_number"] is None
    assert analysis["device"]["platform"] is None

    device_record = client.get(f"/api/devices/{analysis['device']['device_id']}").json()
    assert device_record["device_model"] is None
    assert device_record["serial_number"] is None
    assert device_record["platform"] is None


def test_compliance_evaluation_unaffected_by_device_metadata():
    """Core Invariant: Device metadata does not alter deterministic compliance decisions."""
    controls = load_demo_controls()
    engine = DeterministicControlEngine()

    # Parse compliant cisco with metadata
    with_meta = CiscoParser.parse(
        (ROOT / "configs" / "fixtures" / "cisco_with_device_id.conf").read_text(encoding="utf-8")
    )
    # Parse compliant cisco without metadata
    without_meta = CiscoParser.parse(
        (ROOT / "configs" / "cisco" / "compliant.conf").read_text(encoding="utf-8")
    )

    results_with = engine.evaluate_all(with_meta, controls)
    results_without = engine.evaluate_all(without_meta, controls)

    assert len(results_with) == len(results_without)
    for rw, rwo in zip(results_with, results_without):
        assert rw.control_id == rwo.control_id
        assert rw.result == rwo.result
        assert rw.expected == rwo.expected
        assert rw.actual == rwo.actual


def test_pdf_report_renders_device_identification(client):
    fixture_path = ROOT / "configs" / "fixtures" / "cisco_with_device_id.conf"
    response = client.post(
        "/api/analyze",
        files={"file": ("cisco_with_device_id.conf", fixture_path.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    pdf_response = client.get(f"/api/reports/{analysis_id}/pdf")
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert len(pdf_response.content) > 1000


def test_fortigate_version_only_header_does_not_infer_model_or_platform():
    config = """#config-version=v7.4.3,build2573
config system global
    set hostname "branch-fw-01"
end
"""
    ir = FortiGateParser.parse(config, source_file="fg_ver_only.conf")
    assert ir.device.version == "7.4.3"
    assert ir.device.platform is None
    assert ir.device.device_model is None
    assert ir.device.serial_number is None
    assert "platform" not in ir.device.metadata_provenance
    assert "device_model" not in ir.device.metadata_provenance

