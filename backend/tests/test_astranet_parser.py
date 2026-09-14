from pathlib import Path

import pytest

from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.enums import ComplianceResult, PatternStatus
from app.domain.evidence import build_evidence
from app.parsers.astranet import AstraNetParser, detect_astranet, parse_astranet_config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = PROJECT_ROOT / "configs" / "astranet"
CONTROLS = load_demo_controls()
ENGINE = DeterministicControlEngine()


def read_config(name: str) -> str:
    return (CONFIG_ROOT / name).read_text(encoding="utf-8")


def test_astranet_detection_is_limited_to_synthetic_shape() -> None:
    text = read_config("unknown-pattern.conf")
    assert AstraNetParser.detect(text) is True
    assert detect_astranet(text) is True
    assert AstraNetParser.detect("version 17.9\nhostname router\n") is False


def test_synthetic_astranet_configuration_parses_to_security_ir() -> None:
    security_ir = AstraNetParser.parse(
        read_config("unknown-pattern.conf"),
        source_file="configs/astranet/unknown-pattern.conf",
    )
    assert security_ir.device.vendor == "astranet"
    assert security_ir.device.hostname == "demo-astranet-unknown"
    assert security_ir.normalized_properties == {}
    assert security_ir.provenance == {}


def test_parser_convenience_entry_point_matches_class_entry_point() -> None:
    text = read_config("unknown-pattern.conf")
    assert parse_astranet_config(text).model_dump() == AstraNetParser.parse(text).model_dump()


def test_unknown_pattern_is_preserved_without_a_guessed_semantic_property() -> None:
    source_file = "configs/astranet/unknown-pattern.conf"
    text = read_config("unknown-pattern.conf")
    security_ir = AstraNetParser.parse(text, source_file=source_file)
    pattern = security_ir.unknown_patterns[0]
    expected_line = text.splitlines().index("guard-channel lattice-secure") + 1

    assert pattern.pattern_id == f"astranet-unknown-{expected_line}"
    assert pattern.status is PatternStatus.UNKNOWN
    assert pattern.raw_pattern == "guard-channel lattice-secure"
    assert pattern.source_file == source_file
    assert pattern.line_start == expected_line
    assert pattern.line_end == expected_line
    assert pattern.location is not None
    assert pattern.location.raw_excerpt == "guard-channel lattice-secure"
    assert "approved semantic mapping" in (pattern.reason or "")
    assert "management.ssh_enabled" not in security_ir.normalized_properties


def test_unknown_pattern_is_traced_through_engine_and_evidence() -> None:
    security_ir = AstraNetParser.parse(
        read_config("unknown-pattern.conf"),
        source_file="configs/astranet/unknown-pattern.conf",
    )
    results = ENGINE.evaluate_all(security_ir, CONTROLS)

    assert results
    assert all(result.result is ComplianceResult.UNKNOWN for result in results)
    ssh_result = next(result for result in results if result.control_id == "CTRL-001")
    evidence = build_evidence(security_ir, ssh_result)
    assert evidence[0].result is ComplianceResult.UNKNOWN
    assert evidence[0].source_file is None
    assert security_ir.unknown_patterns[0].location is not None
    assert security_ir.unknown_patterns[0].location.source_file == "configs/astranet/unknown-pattern.conf"
    assert security_ir.unknown_patterns[0].location.line_start == 5
    assert security_ir.unknown_patterns[0].location.raw_excerpt == "guard-channel lattice-secure"


def test_malformed_or_non_astranet_input_is_handled_safely() -> None:
    with pytest.raises(ValueError):
        AstraNetParser.parse("")
    with pytest.raises(ValueError):
        AstraNetParser.parse("# FICTIONAL / SYNTHETIC DEMONSTRATION DATA\nastranet-device demo\n")
    with pytest.raises(TypeError):
        AstraNetParser.parse(None)  # type: ignore[arg-type]
