from pathlib import Path

from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.enums import ComplianceResult
from app.domain.schemas import ControlDefinition, ControlEvaluation, ControlCondition
from app.domain.security_ir import DeviceInfo, SecurityIR, SourceLocation


CONTROLS = {control.control_id: control for control in load_demo_controls()}
ENGINE = DeterministicControlEngine()


def make_security_ir(
    *,
    values: dict[str, object] | None = None,
    with_provenance: bool = True,
) -> SecurityIR:
    properties = values if values is not None else {
        "management.ssh_enabled": True,
        "management.telnet_enabled": False,
        "logging.enabled": True,
        "password_protection.enabled": True,
        "time_sync.ntp_enabled": True,
    }
    provenance = {}
    if with_provenance:
        for index, property_name in enumerate(properties, start=1):
            provenance[property_name] = SourceLocation(
                source_file="configs/cisco/demo-compliant.conf",
                line_start=index,
                line_end=index,
                raw_excerpt=f"demo source for {property_name}",
            )
    return SecurityIR(
        device=DeviceInfo(vendor="cisco_iosxe", version="17.x", hostname="demo-router"),
        normalized_properties=properties,
        provenance=provenance,
    )


def test_ctrl_001_pass() -> None:
    result = ENGINE.evaluate(make_security_ir(), CONTROLS["CTRL-001"])
    assert result.result is ComplianceResult.PASS


def test_ctrl_001_fail() -> None:
    ir = make_security_ir(values={"management.ssh_enabled": True, "management.telnet_enabled": True})
    result = ENGINE.evaluate(ir, CONTROLS["CTRL-001"])
    assert result.result is ComplianceResult.FAIL
    assert result.actual == {"management.ssh_enabled": True, "management.telnet_enabled": True}


def test_ctrl_001_unknown_when_property_is_missing() -> None:
    ir = make_security_ir(values={"management.ssh_enabled": True})
    result = ENGINE.evaluate(ir, CONTROLS["CTRL-001"])
    assert result.result is ComplianceResult.UNKNOWN


def test_ctrl_002_pass() -> None:
    result = ENGINE.evaluate(make_security_ir(), CONTROLS["CTRL-002"])
    assert result.result is ComplianceResult.PASS


def test_ctrl_002_fail() -> None:
    ir = make_security_ir(values={"logging.enabled": False})
    result = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    assert result.result is ComplianceResult.FAIL


def test_ctrl_002_unknown_when_property_is_missing() -> None:
    result = ENGINE.evaluate(make_security_ir(values={}), CONTROLS["CTRL-002"])
    assert result.result is ComplianceResult.UNKNOWN


def test_ctrl_003_pass() -> None:
    result = ENGINE.evaluate(make_security_ir(), CONTROLS["CTRL-003"])
    assert result.result is ComplianceResult.PASS


def test_ctrl_003_fail() -> None:
    ir = make_security_ir(values={"password_protection.enabled": False})
    result = ENGINE.evaluate(ir, CONTROLS["CTRL-003"])
    assert result.result is ComplianceResult.FAIL


def test_ctrl_004_pass() -> None:
    result = ENGINE.evaluate(make_security_ir(), CONTROLS["CTRL-004"])
    assert result.result is ComplianceResult.PASS


def test_ctrl_004_fail() -> None:
    ir = make_security_ir(values={"time_sync.ntp_enabled": False})
    result = ENGINE.evaluate(ir, CONTROLS["CTRL-004"])
    assert result.result is ComplianceResult.FAIL


def test_all_four_controls_evaluate_in_control_order() -> None:
    results = ENGINE.evaluate_all(make_security_ir(), load_demo_controls())
    assert [result.control_id for result in results] == [
        "CTRL-001",
        "CTRL-002",
        "CTRL-003",
        "CTRL-004",
    ]
    assert all(result.result is ComplianceResult.PASS for result in results)


def test_evidence_source_is_preserved() -> None:
    result = ENGINE.evaluate(make_security_ir(), CONTROLS["CTRL-001"])
    evidence = next(item for item in result.evidence if item.property == "management.ssh_enabled")
    assert evidence.source_file == "configs/cisco/demo-compliant.conf"
    assert evidence.line_start == 1


def test_evidence_raw_excerpt_is_preserved() -> None:
    result = ENGINE.evaluate(make_security_ir(), CONTROLS["CTRL-002"])
    assert result.evidence[0].raw_excerpt == "demo source for logging.enabled"


def test_missing_property_produces_unknown_evidence() -> None:
    result = ENGINE.evaluate(make_security_ir(values={}), CONTROLS["CTRL-004"])
    assert result.result is ComplianceResult.UNKNOWN
    assert result.evidence[0].actual is None
    assert result.evidence[0].result is ComplianceResult.UNKNOWN


def test_partial_information_is_unknown_for_all_group() -> None:
    ir = make_security_ir(values={"management.ssh_enabled": True})
    result = ENGINE.evaluate(ir, CONTROLS["CTRL-001"])
    assert result.result is ComplianceResult.UNKNOWN
    assert "could not establish" in result.explanation


def test_missing_provenance_does_not_produce_authoritative_pass_or_fail() -> None:
    ir = make_security_ir(with_provenance=False)
    result = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    assert result.result is ComplianceResult.UNKNOWN
    assert result.evidence[0].source_file is None


def test_explicit_unknown_property_value_produces_unknown() -> None:
    ir = make_security_ir(values={"logging.enabled": None})
    result = ENGINE.evaluate(ir, CONTROLS["CTRL-002"])
    assert result.result is ComplianceResult.UNKNOWN
    assert result.evidence[0].actual is None


def test_unsupported_operator_produces_unknown() -> None:
    control = CONTROLS["CTRL-002"].model_copy(deep=True)
    control.evaluation.conditions[0].operator = "contains"
    result = ENGINE.evaluate(make_security_ir(), control)
    assert result.result is ComplianceResult.UNKNOWN
    assert "not supported" in result.evidence[0].explanation


def test_unsupported_evaluation_group_produces_unknown() -> None:
    control = CONTROLS["CTRL-002"].model_copy(
        update={"evaluation": ControlEvaluation(type="any", conditions=[ControlCondition(path="logging.enabled", operator="equals", expected=True)])}
    )
    result = ENGINE.evaluate(make_security_ir(), control)
    assert result.result is ComplianceResult.UNKNOWN


def test_explicit_not_applicable_is_supported() -> None:
    control = ControlDefinition(
        control_id="CTRL-NA",
        name="Explicit demo N/A",
        description="Only a contract test for explicit N/A.",
        expected_value="Not applicable",
        evaluation=ControlEvaluation(type="not_applicable"),
    )
    result = ENGINE.evaluate(make_security_ir(), control)
    assert result.result is ComplianceResult.NOT_APPLICABLE


def test_same_input_produces_identical_result_and_evidence() -> None:
    ir = make_security_ir(values={"logging.enabled": False})
    control = CONTROLS["CTRL-002"]
    first = ENGINE.evaluate(ir, control)
    second = ENGINE.evaluate(ir, control)
    assert first == second
    assert first.model_dump() == second.model_dump()


def test_controls_are_loaded_from_yaml_not_hard_coded_in_engine() -> None:
    controls_path = Path("controls/demo_controls.yaml")
    assert controls_path.exists()
    assert set(CONTROLS) == {"CTRL-001", "CTRL-002", "CTRL-003", "CTRL-004"}
