from pathlib import Path

import pytest

from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.enums import ComplianceResult, PatternStatus
from app.domain.evidence import build_evidence
from app.parsers.cisco import CiscoParser
from app.parsers.fortigate import FortiGateParser, detect_fortigate, parse_fortigate_config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = PROJECT_ROOT / "configs" / "fortigate"
CONTROLS = load_demo_controls()
CONTROL_BY_ID = {control.control_id: control for control in CONTROLS}
ENGINE = DeterministicControlEngine()


def read_config(name: str) -> str:
    return (CONFIG_ROOT / name).read_text(encoding="utf-8")


def test_fortigate_vendor_detection() -> None:
    text = read_config("compliant.conf")
    assert FortiGateParser.detect(text) is True
    assert detect_fortigate(text) is True
    assert FortiGateParser.detect("version 17.9\nhostname cisco\n") is False


def test_valid_fortigate_configuration_parses_to_security_ir() -> None:
    security_ir = FortiGateParser.parse(
        read_config("compliant.conf"),
        source_file="configs/fortigate/compliant.conf",
    )
    assert security_ir.device.vendor == "fortigate_fortios"
    assert security_ir.device.version == "7.4.3"
    assert security_ir.device.hostname == "demo-fortigate-compliant"


def test_parser_convenience_entry_point_matches_class_entry_point() -> None:
    text = read_config("compliant.conf")
    assert parse_fortigate_config(text).model_dump() == FortiGateParser.parse(text).model_dump()


def test_fortigate_normalized_properties_are_supported() -> None:
    compliant = FortiGateParser.parse(read_config("compliant.conf"))
    noncompliant = FortiGateParser.parse(read_config("noncompliant.conf"))
    assert compliant.normalized_properties == {
        "management.ssh_enabled": True,
        "management.telnet_enabled": False,
        "logging.enabled": True,
        "password_protection.enabled": True,
        "time_sync.ntp_enabled": True,
    }
    assert noncompliant.normalized_properties == {
        "management.ssh_enabled": False,
        "management.telnet_enabled": True,
        "logging.enabled": False,
        "password_protection.enabled": False,
        "time_sync.ntp_enabled": False,
    }


def test_fortigate_provenance_preserves_exact_lines_and_excerpts() -> None:
    text = read_config("compliant.conf")
    security_ir = FortiGateParser.parse(text, source_file="configs/fortigate/compliant.conf")
    allowaccess_line = text.splitlines().index("        set allowaccess ping https ssh") + 1
    assert security_ir.provenance["management.ssh_enabled"].source_file == "configs/fortigate/compliant.conf"
    assert security_ir.provenance["management.ssh_enabled"].line_start == allowaccess_line
    assert security_ir.provenance["management.ssh_enabled"].line_end == allowaccess_line
    assert security_ir.provenance["management.ssh_enabled"].raw_excerpt == "        set allowaccess ping https ssh"


def test_fortigate_password_policy_and_ntp_mappings_preserve_source() -> None:
    security_ir = FortiGateParser.parse(read_config("compliant.conf"))
    assert security_ir.provenance["password_protection.enabled"].raw_excerpt == "    set status enable"
    assert security_ir.provenance["time_sync.ntp_enabled"].raw_excerpt == "    set ntpsync enable"


def test_missing_information_is_not_converted_to_false() -> None:
    security_ir = FortiGateParser.parse(read_config("unknown.conf"))
    assert security_ir.normalized_properties == {}
    assert all(
        ENGINE.evaluate(security_ir, control).result is ComplianceResult.UNKNOWN
        for control in CONTROLS
    )


def test_unsupported_allowaccess_syntax_is_unknown() -> None:
    text = """# SYNTHETIC DEMONSTRATION CONFIGURATION
config system interface
    edit \"port1\"
        set allowaccess ping future-protocol
    next
end
"""
    security_ir = FortiGateParser.parse(text)
    assert security_ir.normalized_properties == {}
    assert security_ir.unknown_patterns
    assert security_ir.unknown_patterns[0].status is PatternStatus.UNKNOWN


def test_ambiguous_status_is_preserved_as_unknown() -> None:
    text = """# SYNTHETIC DEMONSTRATION CONFIGURATION
config log disk setting
    set status enable
    set status disable
end
"""
    security_ir = FortiGateParser.parse(text)
    assert security_ir.normalized_properties["logging.enabled"] is None
    result = ENGINE.evaluate(security_ir, CONTROL_BY_ID["CTRL-002"])
    assert result.result is ComplianceResult.UNKNOWN


def test_fortigate_compliant_parser_engine_evidence_integration() -> None:
    security_ir = FortiGateParser.parse(
        read_config("compliant.conf"),
        source_file="configs/fortigate/compliant.conf",
    )
    results = ENGINE.evaluate_all(security_ir, CONTROLS)
    assert all(result.result is ComplianceResult.PASS for result in results)
    evidence = build_evidence(security_ir, next(result for result in results if result.control_id == "CTRL-002"))
    assert evidence[0].control_id == "CTRL-002"
    assert evidence[0].source_file == "configs/fortigate/compliant.conf"
    assert evidence[0].raw_excerpt == "    set status enable"


def test_fortigate_noncompliant_parser_engine_integration() -> None:
    security_ir = FortiGateParser.parse(read_config("noncompliant.conf"))
    result_by_id = {
        result.control_id: result
        for result in ENGINE.evaluate_all(security_ir, CONTROLS)
    }
    assert result_by_id["CTRL-001"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-002"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-003"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-004"].result is ComplianceResult.FAIL


def test_cisco_and_fortigate_use_identical_normalized_property_names() -> None:
    cisco_ir = CiscoParser.parse((PROJECT_ROOT / "configs" / "cisco" / "compliant.conf").read_text(encoding="utf-8"))
    fortigate_ir = FortiGateParser.parse(read_config("compliant.conf"))
    assert set(cisco_ir.normalized_properties) == set(fortigate_ir.normalized_properties)
    assert set(cisco_ir.provenance) == set(fortigate_ir.provenance)
    assert fortigate_ir.normalized_properties["management.ssh_enabled"] is True


def test_malformed_or_unsupported_input_is_handled_safely() -> None:
    with pytest.raises(ValueError):
        FortiGateParser.parse("")
    with pytest.raises(ValueError):
        FortiGateParser.parse("version 17.9\nhostname not-fortigate\n")
    with pytest.raises(TypeError):
        FortiGateParser.parse(None)  # type: ignore[arg-type]


def test_malformed_hostname_does_not_crash_or_fabricate_metadata() -> None:
    text = """# SYNTHETIC DEMONSTRATION CONFIGURATION
config system global
    set hostname \"unterminated
end
"""
    security_ir = FortiGateParser.parse(text)
    assert security_ir.device.hostname is None
    assert security_ir.unknown_patterns
