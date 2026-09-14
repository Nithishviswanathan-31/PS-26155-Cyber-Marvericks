from pathlib import Path

import pytest

from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.enums import ComplianceResult, PatternStatus
from app.domain.evidence import build_evidence
from app.parsers.cisco import CiscoParser
from app.parsers.fortigate import FortiGateParser
from app.parsers.paloalto import PaloAltoParser, detect_paloalto, parse_paloalto_config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = PROJECT_ROOT / "configs" / "paloalto"
CONTROLS = load_demo_controls()
CONTROL_BY_ID = {control.control_id: control for control in CONTROLS}
ENGINE = DeterministicControlEngine()


def read_config(name: str) -> str:
    return (CONFIG_ROOT / name).read_text(encoding="utf-8")


def test_paloalto_vendor_detection() -> None:
    text = read_config("compliant.conf")
    assert PaloAltoParser.detect(text) is True
    assert detect_paloalto(text) is True
    assert PaloAltoParser.detect("version 17.9\nhostname cisco\n") is False


def test_valid_panos_configuration_parses_to_security_ir() -> None:
    security_ir = PaloAltoParser.parse(
        read_config("compliant.conf"),
        source_file="configs/paloalto/compliant.conf",
    )
    assert security_ir.device.vendor == "paloalto_panos"
    assert security_ir.device.hostname == "demo-paloalto-compliant"
    assert security_ir.device.version is None


def test_parser_convenience_entry_point_matches_class_entry_point() -> None:
    text = read_config("compliant.conf")
    assert parse_paloalto_config(text).model_dump() == PaloAltoParser.parse(text).model_dump()


def test_panos_management_access_mapping_requires_an_assigned_profile() -> None:
    compliant = PaloAltoParser.parse(read_config("compliant.conf"))
    noncompliant = PaloAltoParser.parse(read_config("noncompliant.conf"))
    assert compliant.normalized_properties["management.ssh_enabled"] is True
    assert compliant.normalized_properties["management.telnet_enabled"] is False
    assert noncompliant.normalized_properties["management.ssh_enabled"] is False
    assert noncompliant.normalized_properties["management.telnet_enabled"] is True

    unassigned = PaloAltoParser.parse(
        "set deviceconfig system hostname unassigned\n"
        "set network profiles interface-management-profile unused ssh yes\n"
        "set network profiles interface-management-profile unused telnet no\n"
    )
    assert "management.ssh_enabled" not in unassigned.normalized_properties


def test_panos_logging_password_and_ntp_mappings() -> None:
    security_ir = PaloAltoParser.parse(read_config("compliant.conf"))
    assert security_ir.normalized_properties["logging.enabled"] is True
    assert security_ir.normalized_properties["password_protection.enabled"] is True
    assert security_ir.normalized_properties["time_sync.ntp_enabled"] is True

    noncompliant = PaloAltoParser.parse(read_config("noncompliant.conf"))
    assert noncompliant.normalized_properties["logging.enabled"] is False
    assert noncompliant.normalized_properties["password_protection.enabled"] is False
    assert "time_sync.ntp_enabled" not in noncompliant.normalized_properties


def test_panos_provenance_preserves_source_line_and_raw_excerpt() -> None:
    text = read_config("compliant.conf")
    security_ir = PaloAltoParser.parse(text, source_file="configs/paloalto/compliant.conf")
    log_line = text.splitlines().index(
        "set shared log-settings system match-list system-audit send-to-panorama yes"
    ) + 1
    location = security_ir.provenance["logging.enabled"]
    assert location.source_file == "configs/paloalto/compliant.conf"
    assert location.line_start == log_line
    assert location.line_end == log_line
    assert location.raw_excerpt == "set shared log-settings system match-list system-audit send-to-panorama yes"


def test_missing_information_remains_unknown_at_control_engine_stage() -> None:
    security_ir = PaloAltoParser.parse(read_config("unknown.conf"))
    assert security_ir.normalized_properties == {}
    assert all(
        ENGINE.evaluate(security_ir, control).result is ComplianceResult.UNKNOWN
        for control in CONTROLS
    )


def test_ambiguous_panos_setting_remains_unknown() -> None:
    text = """# SYNTHETIC DEMONSTRATION CONFIGURATION
set deviceconfig system hostname ambiguous
set shared log-settings system match-list system-audit send-to-panorama yes
set shared log-settings system match-list system-audit send-to-panorama no
"""
    security_ir = PaloAltoParser.parse(text)
    assert security_ir.normalized_properties["logging.enabled"] is None
    result = ENGINE.evaluate(security_ir, CONTROL_BY_ID["CTRL-002"])
    assert result.result is ComplianceResult.UNKNOWN


def test_unsupported_panos_syntax_does_not_fabricate_properties() -> None:
    text = """# SYNTHETIC DEMONSTRATION CONFIGURATION
set deviceconfig system hostname unsupported
set deviceconfig system service disable-telnet yes
"""
    security_ir = PaloAltoParser.parse(text)
    assert "management.telnet_enabled" not in security_ir.normalized_properties
    assert security_ir.unknown_patterns
    assert security_ir.unknown_patterns[0].status is PatternStatus.UNKNOWN


def test_panos_parser_engine_evidence_compliant_integration() -> None:
    security_ir = PaloAltoParser.parse(
        read_config("compliant.conf"),
        source_file="configs/paloalto/compliant.conf",
    )
    results = ENGINE.evaluate_all(security_ir, CONTROLS)
    assert all(result.result is ComplianceResult.PASS for result in results)
    logging_result = next(result for result in results if result.control_id == "CTRL-002")
    evidence = build_evidence(security_ir, logging_result)
    assert evidence[0].source_file == "configs/paloalto/compliant.conf"
    assert evidence[0].line_start == 6
    assert evidence[0].raw_excerpt == "set shared log-settings system match-list system-audit send-to-panorama yes"


def test_panos_parser_engine_noncompliant_integration() -> None:
    security_ir = PaloAltoParser.parse(read_config("noncompliant.conf"))
    result_by_id = {
        result.control_id: result
        for result in ENGINE.evaluate_all(security_ir, CONTROLS)
    }
    assert result_by_id["CTRL-001"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-002"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-003"].result is ComplianceResult.FAIL
    assert result_by_id["CTRL-004"].result is ComplianceResult.UNKNOWN


def test_three_vendor_normalization_uses_common_property_names() -> None:
    cisco = CiscoParser.parse(
        (PROJECT_ROOT / "configs" / "cisco" / "compliant.conf").read_text(encoding="utf-8")
    )
    fortigate = FortiGateParser.parse(
        (PROJECT_ROOT / "configs" / "fortigate" / "compliant.conf").read_text(encoding="utf-8")
    )
    paloalto = PaloAltoParser.parse(read_config("compliant.conf"))
    expected_properties = set(cisco.normalized_properties)
    assert expected_properties == set(fortigate.normalized_properties)
    assert expected_properties == set(paloalto.normalized_properties)
    assert "management.ssh_enabled" in paloalto.normalized_properties


def test_three_vendor_control_engine_reuses_the_same_control_definitions() -> None:
    cisco = CiscoParser.parse(
        (PROJECT_ROOT / "configs" / "cisco" / "compliant.conf").read_text(encoding="utf-8")
    )
    fortigate = FortiGateParser.parse(
        (PROJECT_ROOT / "configs" / "fortigate" / "compliant.conf").read_text(encoding="utf-8")
    )
    paloalto = PaloAltoParser.parse(read_config("compliant.conf"))
    for security_ir in (cisco, fortigate, paloalto):
        assert all(
            result.result is ComplianceResult.PASS
            for result in ENGINE.evaluate_all(security_ir, CONTROLS)
        )


def test_malformed_or_unsupported_input_is_handled_safely() -> None:
    with pytest.raises(ValueError):
        PaloAltoParser.parse("")
    with pytest.raises(ValueError):
        PaloAltoParser.parse("<config><deviceconfig /></config>")
    with pytest.raises(TypeError):
        PaloAltoParser.parse(None)  # type: ignore[arg-type]


def test_malformed_set_statement_does_not_crash() -> None:
    with pytest.raises(ValueError):
        PaloAltoParser.parse(
            'set deviceconfig system hostname "unterminated\n'
        )
