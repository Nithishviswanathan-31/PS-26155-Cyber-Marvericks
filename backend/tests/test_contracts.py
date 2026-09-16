import json
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import load_demo_controls
from app.domain.enums import ComplianceResult, PatternStatus
from app.domain.security_ir import (
    DeviceInfo,
    SecurityIR,
    SourceLocation,
    UnknownPattern,
)
from app.main import app


def test_result_enum_contains_all_contract_states() -> None:
    assert {item.value for item in ComplianceResult} == {
        "PASS",
        "FAIL",
        "PARTIAL",
        "NOT_APPLICABLE",
        "UNKNOWN",
    }


def test_pattern_enum_contains_all_contract_states() -> None:
    assert {item.value for item in PatternStatus} == {
        "KNOWN",
        "UNKNOWN",
        "SUGGESTED",
        "APPROVED",
        "RECOGNIZED",
    }


def test_security_ir_validates_with_provenance_and_unknown_pattern() -> None:
    security_ir = SecurityIR(
        device=DeviceInfo(vendor="cisco_iosxe", version="17.x", hostname="demo-router"),
        normalized_properties={"management.ssh_enabled": True},
        provenance={
            "management.ssh_enabled": SourceLocation(
                source_file="demo.conf",
                line_start=10,
                line_end=10,
                raw_excerpt="transport input ssh",
            )
        },
        unknown_patterns=[
            UnknownPattern(
                pattern_id="pattern-001",
                raw_pattern="fictional unknown directive",
                location=SourceLocation(source_file="demo.conf", line_start=20),
            )
        ],
    )

    assert security_ir.schema_version == "0.1"
    assert security_ir.device.vendor == "cisco_iosxe"
    assert security_ir.provenance["management.ssh_enabled"].line_start == 10
    assert security_ir.unknown_patterns[0].status is PatternStatus.UNKNOWN
    assert security_ir.device.device_model is None
    assert security_ir.device.serial_number is None


def test_security_ir_serializes_and_loads_back() -> None:
    fixture_path = Path("configs/fixtures/sample_security_ir.json")
    fixture_payload = fixture_path.read_text(encoding="utf-8")

    original = SecurityIR.model_validate_json(fixture_payload)
    round_trip = SecurityIR.model_validate_json(original.model_dump_json())

    assert round_trip == original
    assert json.loads(round_trip.model_dump_json())["schema_version"] == "0.1"


def test_valid_provenance_validates() -> None:
    location = SourceLocation(
        source_file="configs/cisco/compliant.conf",
        line_start=18,
        line_end=18,
        raw_excerpt="transport input ssh",
    )

    assert location.source_file == "configs/cisco/compliant.conf"
    assert location.line_start == 18


def test_invalid_provenance_is_rejected() -> None:
    try:
        SourceLocation(source_file=" ", line_start=0)
    except ValidationError:
        pass
    else:
        raise AssertionError("invalid provenance should be rejected")

    try:
        SourceLocation(source_file="demo.conf", line_start=12, line_end=11)
    except ValidationError:
        pass
    else:
        raise AssertionError("reversed provenance range should be rejected")


def test_unknown_pattern_supports_explicit_source_fields() -> None:
    pattern = UnknownPattern(
        pattern_id="pattern-002",
        raw_pattern="secure-channel ciphered",
        source_file="configs/astranet/unknown-pattern.conf",
        line_start=7,
        line_end=7,
        reason="No approved semantic mapping exists yet.",
    )

    assert pattern.status is PatternStatus.UNKNOWN
    assert pattern.location is not None
    assert pattern.location.source_file == pattern.source_file
    assert pattern.location.line_start == 7


def test_multiple_normalized_properties_can_coexist() -> None:
    security_ir = SecurityIR(
        device=DeviceInfo(vendor="fortigate_fortios", hostname="demo-firewall"),
        normalized_properties={
            "management.ssh_enabled": True,
            "management.telnet_enabled": False,
            "logging.enabled": True,
            "password_protection.enabled": False,
            "time_sync.ntp_enabled": True,
            "future.demo_property": {"enabled": True},
        },
    )

    assert len(security_ir.normalized_properties) == 6
    assert security_ir.normalized_properties["future.demo_property"]["enabled"] is True


def test_property_can_be_traced_to_its_source_location() -> None:
    security_ir = SecurityIR(
        device=DeviceInfo(vendor="cisco_iosxe", hostname="demo-router"),
        normalized_properties={"management.ssh_enabled": True},
        provenance={
            "management.ssh_enabled": SourceLocation(
                source_file="configs/cisco/compliant.conf",
                line_start=18,
                line_end=18,
                raw_excerpt="transport input ssh",
            )
        },
    )

    trace = security_ir.trace_property("management.ssh_enabled")

    assert trace is not None
    assert trace.property == "management.ssh_enabled"
    assert trace.value is True
    assert trace.provenance is not None
    assert trace.provenance.source_file == "configs/cisco/compliant.conf"
    assert trace.provenance.line_start == 18
    assert trace.provenance.raw_excerpt == "transport input ssh"


def test_control_yaml_loads_six_controls_preserving_original_four() -> None:
    controls = load_demo_controls()

    assert len(controls) == 6
    assert [control.control_id for control in controls] == [
        "CTRL-001",
        "CTRL-002",
        "CTRL-003",
        "CTRL-004",
        "CTRL-005",
        "CTRL-006",
    ]
    assert all(control.remediation for control in controls[:4])
    assert all(not control.remediation for control in controls[4:])
    assert Path("controls/demo_controls.yaml").exists()


def test_health_endpoint_returns_exact_contract() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
