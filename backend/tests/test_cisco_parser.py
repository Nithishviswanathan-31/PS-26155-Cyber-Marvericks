from pathlib import Path

import pytest

from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.enums import ComplianceResult, PatternStatus
from app.parsers.cisco import CiscoParser, detect_cisco, parse_cisco_config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = PROJECT_ROOT / "configs" / "cisco"
CONTROLS = load_demo_controls()
CONTROL_BY_ID = {control.control_id: control for control in CONTROLS}
ENGINE = DeterministicControlEngine()


def read_config(name: str) -> str:
    return (CONFIG_ROOT / name).read_text(encoding="utf-8")


def test_cisco_vendor_detection() -> None:
    text = read_config("compliant.conf")
    assert CiscoParser.detect(text) is True
    assert detect_cisco(text) is True
    assert CiscoParser.detect("<panos><config /></panos>") is False


def test_valid_cisco_configuration_parses_to_security_ir() -> None:
    security_ir = CiscoParser.parse(read_config("compliant.conf"), source_file="configs/cisco/compliant.conf")
    assert security_ir.device.vendor == "cisco_iosxe"
    assert security_ir.device.version == "17.9"
    assert security_ir.device.hostname == "demo-cisco-compliant"


def test_parser_convenience_entry_point_matches_class_entry_point() -> None:
    text = read_config("compliant.conf")
    assert parse_cisco_config(text).model_dump() == CiscoParser.parse(text).model_dump()


def test_ssh_property_is_parsed_correctly() -> None:
    security_ir = CiscoParser.parse(read_config("compliant.conf"))
    assert security_ir.normalized_properties["management.ssh_enabled"] is True


def test_telnet_state_is_parsed_correctly() -> None:
    compliant = CiscoParser.parse(read_config("compliant.conf"))
    noncompliant = CiscoParser.parse(read_config("noncompliant.conf"))
    assert compliant.normalized_properties["management.telnet_enabled"] is False
    assert noncompliant.normalized_properties["management.telnet_enabled"] is True


def test_logging_state_is_parsed_correctly() -> None:
    compliant = CiscoParser.parse(read_config("compliant.conf"))
    noncompliant = CiscoParser.parse(read_config("noncompliant.conf"))
    assert compliant.normalized_properties["logging.enabled"] is True
    assert noncompliant.normalized_properties["logging.enabled"] is False


def test_password_protection_state_is_parsed_correctly() -> None:
    compliant = CiscoParser.parse(read_config("compliant.conf"))
    noncompliant = CiscoParser.parse(read_config("noncompliant.conf"))
    assert compliant.normalized_properties["password_protection.enabled"] is True
    assert noncompliant.normalized_properties["password_protection.enabled"] is False


def test_ntp_state_is_parsed_correctly() -> None:
    compliant = CiscoParser.parse(read_config("compliant.conf"))
    noncompliant = CiscoParser.parse(read_config("noncompliant.conf"))
    assert compliant.normalized_properties["time_sync.ntp_enabled"] is True
    assert noncompliant.normalized_properties["time_sync.ntp_enabled"] is False


def test_provenance_exists_for_every_parsed_property() -> None:
    security_ir = CiscoParser.parse(
        read_config("compliant.conf"),
        source_file="configs/cisco/compliant.conf",
    )
    assert set(security_ir.normalized_properties) == set(security_ir.provenance)
    assert security_ir.provenance["management.ssh_enabled"].source_file == "configs/cisco/compliant.conf"


def test_source_line_numbers_match_original_input() -> None:
    text = read_config("compliant.conf")
    security_ir = CiscoParser.parse(text, source_file="configs/cisco/compliant.conf")
    ssh_line = text.splitlines().index(" transport input ssh") + 1
    assert security_ir.provenance["management.ssh_enabled"].line_start == ssh_line
    assert security_ir.provenance["management.ssh_enabled"].line_end == ssh_line


def test_raw_source_excerpt_is_preserved() -> None:
    security_ir = CiscoParser.parse(read_config("compliant.conf"))
    assert security_ir.provenance["management.ssh_enabled"].raw_excerpt == " transport input ssh"


def test_missing_security_configuration_is_not_fabricated() -> None:
    security_ir = CiscoParser.parse(read_config("unknown.conf"))
    assert "management.ssh_enabled" not in security_ir.normalized_properties
    assert "logging.enabled" not in security_ir.normalized_properties
    assert "password_protection.enabled" not in security_ir.normalized_properties
    assert "time_sync.ntp_enabled" not in security_ir.normalized_properties
    assert security_ir.unknown_patterns
    assert all(pattern.status is PatternStatus.UNKNOWN for pattern in security_ir.unknown_patterns)


def test_missing_property_becomes_unknown_at_control_engine_stage() -> None:
    security_ir = CiscoParser.parse(read_config("unknown.conf"))
    result = ENGINE.evaluate(security_ir, CONTROL_BY_ID["CTRL-002"])
    assert result.result is ComplianceResult.UNKNOWN


def test_conflicting_configuration_is_explicitly_unknown() -> None:
    text = """! SYNTHETIC DEMO DATA
version 17.9
hostname conflict-demo
logging buffered 16384
no logging buffered 16384
"""
    security_ir = CiscoParser.parse(text)
    assert security_ir.normalized_properties["logging.enabled"] is None
    result = ENGINE.evaluate(security_ir, CONTROL_BY_ID["CTRL-002"])
    assert result.result is ComplianceResult.UNKNOWN


def test_malformed_or_unsupported_input_is_handled_safely() -> None:
    with pytest.raises(ValueError):
        CiscoParser.parse("")
    with pytest.raises(ValueError):
        CiscoParser.parse("not a Cisco configuration")
    with pytest.raises(TypeError):
        CiscoParser.parse(None)  # type: ignore[arg-type]


def test_parser_to_engine_compliant_vertical_slice() -> None:
    security_ir = CiscoParser.parse(read_config("compliant.conf"), source_file="configs/cisco/compliant.conf")
    results = ENGINE.evaluate_all(security_ir, CONTROLS)
    assert all(result.result is ComplianceResult.PASS for result in results)
    assert all(result.evidence for result in results)


def test_parser_to_engine_noncompliant_vertical_slice() -> None:
    security_ir = CiscoParser.parse(read_config("noncompliant.conf"), source_file="configs/cisco/noncompliant.conf")
    results = ENGINE.evaluate_all(security_ir, CONTROLS)
    result_by_id = {result.control_id: result for result in results}
    assert result_by_id["CTRL-001"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-002"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-003"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-004"].result is ComplianceResult.FAIL

