from pathlib import Path

from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.enums import ComplianceResult
from app.domain.evidence import EvidenceRecord, build_evidence
from app.domain.security_ir import DeviceInfo, SecurityIR, SourceLocation
from app.parsers.cisco import CiscoParser


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = PROJECT_ROOT / "configs" / "cisco"
CONTROLS = {control.control_id: control for control in load_demo_controls()}
ENGINE = DeterministicControlEngine()


def parse_fixture(name: str, source_file: str | None = None) -> SecurityIR:
    text = (CONFIG_ROOT / name).read_text(encoding="utf-8")
    return CiscoParser.parse(text, source_file=source_file or f"configs/cisco/{name}")


def test_pass_result_creates_evidence() -> None:
    ir = parse_fixture("compliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)
    assert len(evidence) == 1
    assert evidence[0].result is ComplianceResult.PASS


def test_fail_result_creates_evidence() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)
    assert evidence[0].result is ComplianceResult.FAIL
    assert evidence[0].condition_result is ComplianceResult.FAIL


def test_unknown_result_can_be_represented() -> None:
    ir = parse_fixture("unknown.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)
    assert evaluation.result is ComplianceResult.UNKNOWN
    assert evidence[0].result is ComplianceResult.UNKNOWN


def test_source_file_is_preserved() -> None:
    ir = parse_fixture("noncompliant.conf", "configs/cisco/noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)[0]
    assert evidence.source_file == "configs/cisco/noncompliant.conf"


def test_source_line_is_preserved() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)[0]
    assert evidence.line_start == 5
    assert evidence.line_end == 5


def test_raw_excerpt_is_preserved() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)[0]
    assert evidence.raw_excerpt == "no logging buffered 16384"


def test_expected_value_is_preserved() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    assert build_evidence(ir, evaluation)[0].expected is True


def test_actual_value_is_preserved_from_security_ir_trace() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    assert build_evidence(ir, evaluation)[0].actual is False


def test_explanations_are_preserved() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)[0]
    assert evidence.explanation == "logging.enabled was False, but the expected value is True."
    assert evidence.control_explanation == evaluation.explanation


def test_multi_property_control_creates_separate_evidence_entries() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-001"])
    evidence = build_evidence(ir, evaluation)
    assert [item.property for item in evidence] == [
        "management.ssh_enabled",
        "management.telnet_enabled",
    ]
    assert all(item.source_file == "configs/cisco/noncompliant.conf" for item in evidence)
    assert all(item.line_start == 8 for item in evidence)


def test_missing_provenance_does_not_fabricate_information() -> None:
    ir = SecurityIR(
        device=DeviceInfo(vendor="cisco_iosxe", version="17.9", hostname="demo"),
        normalized_properties={"logging.enabled": False},
    )
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)[0]
    assert evaluation.result is ComplianceResult.UNKNOWN
    assert evidence.source_file is None
    assert evidence.line_start is None
    assert evidence.raw_excerpt is None


def test_missing_property_does_not_fabricate_information() -> None:
    ir = SecurityIR(
        device=DeviceInfo(vendor="cisco_iosxe", hostname="demo"),
        normalized_properties={},
    )
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    evidence = build_evidence(ir, evaluation)[0]
    assert evidence.actual is None
    assert evidence.source_file is None
    assert evidence.raw_excerpt is None


def test_evidence_generation_does_not_change_control_result() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    original_result = evaluation.result
    build_evidence(ir, evaluation)
    assert evaluation.result is original_result


def test_evidence_is_deterministic_for_same_input() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    first = build_evidence(ir, evaluation)
    second = build_evidence(ir, evaluation)
    assert first == second
    assert first[0].model_dump() == second[0].model_dump()


def test_evidence_model_serializes_and_loads() -> None:
    ir = parse_fixture("noncompliant.conf")
    evaluation = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    original = build_evidence(ir, evaluation)[0]
    restored = EvidenceRecord.model_validate_json(original.model_dump_json())
    assert restored == original


def test_evidence_model_rejects_reversed_lines() -> None:
    try:
        EvidenceRecord(
            property="logging.enabled",
            expected=True,
            actual=False,
            result=ComplianceResult.FAIL,
            source_file="demo.conf",
            line_start=5,
            line_end=4,
            explanation="demo",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("reversed evidence lines should be rejected")


def test_evidence_model_accepts_missing_source_for_unknown() -> None:
    record = EvidenceRecord(
        property="logging.enabled",
        expected=True,
        actual=None,
        result=ComplianceResult.UNKNOWN,
        explanation="Source is unavailable.",
    )
    assert record.source_file is None
