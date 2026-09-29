"""V2.1 metadata contracts and deterministic boundary regression coverage."""
from pathlib import Path
from typing import get_args

import pytest
import yaml
from pydantic import ValidationError

from app.config import load_demo_controls, CatalogueError
from app.domain.control_engine import DeterministicControlEngine
from app.domain.evidence import build_evidence
from app.domain.schemas import ControlCategory, ControlDefinition, ControlSeverity, FrameworkMapping
from app.parsers.cisco import CiscoParser
from app.parsers.fortigate import FortiGateParser
from app.parsers.paloalto import PaloAltoParser
from app.parsers.astranet import AstraNetParser
from app.services.remediation_service import _REMEDIATIONS

ROOT = Path(__file__).resolve().parents[2]
CONTROLS = load_demo_controls()
ENGINE = DeterministicControlEngine()
VENDORS = [("cisco", CiscoParser), ("fortigate", FortiGateParser), ("paloalto", PaloAltoParser)]


def definition(**updates):
    return ControlDefinition.model_validate(CONTROLS[0].model_dump() | updates)


@pytest.mark.parametrize("category", get_args(ControlCategory))
def test_valid_categories(category):
    assert definition(category=category).category == category


@pytest.mark.parametrize("severity", get_args(ControlSeverity))
def test_valid_severities(severity):
    assert definition(severity=severity).severity == severity


@pytest.mark.parametrize("updates", [
    {"category": "OTHER"}, {"severity": "URGENT"}, {"enabled": "true"},
    {"applicable_vendors": ["cisco"]}, {"framework_mappings": [{"framework_name": "Example"}]},
    {"framework_mappings": [{"framework_name": " ", "reference_id": "test"}]},
    {"evidence_requirements": {"include_paths": ["invented.property"]}},
    {"evidence_requirements": {"include_paths": [], "display_fields": ["fabricated"]}},
    {"remediation_reference": {"astranet": " "}},
    {"remediation_reference": {"unknown_vendor": "test"}},
])
def test_invalid_metadata_is_rejected(updates):
    with pytest.raises(ValidationError):
        definition(**updates)


@pytest.mark.parametrize("vendor", ["cisco_iosxe", "fortigate_fortios", "paloalto_panos", "astranet"])
def test_schema_accepts_existing_vendor_identifiers(vendor):
    assert definition(applicable_vendors=[vendor]).applicable_vendors == [vendor]


def test_framework_structure_and_catalogue_mappings():
    mapping = FrameworkMapping(framework_name="Synthetic test framework", framework_version="test",
                               reference_id="TEST-ONLY", title="Example", description="Test data, not official")
    assert definition(framework_mappings=[mapping]).framework_mappings == [mapping]
    assert all(isinstance(control.framework_mappings, list) and len(control.framework_mappings) > 0 for control in CONTROLS)


def test_evidence_contract_and_remediation_references():
    for control in CONTROLS:
        requirements = control.evidence_requirements
        assert set(requirements.include_paths) == {c.path for c in control.evaluation.conditions}
        assert {"actual", "expected", "source_file", "line_start", "evidence_source", "result"} <= set(requirements.display_fields)
        if control.control_id in {"CTRL-001", "CTRL-002", "CTRL-003", "CTRL-004"}:
            for vendor, reference in control.remediation_reference.items():
                assert _REMEDIATIONS[(vendor, control.control_id)].remediation_id == reference
        else:
            assert control.remediation_reference is None


def test_legacy_definition_remains_valid():
    payload = CONTROLS[0].model_dump(include={"control_id", "name", "description", "expected_value", "evaluation", "evidence_rule", "remediation"})
    legacy = ControlDefinition.model_validate(payload)
    assert legacy.enabled and legacy.category is None and legacy.severity is None
    assert legacy.framework_mappings == [] and legacy.evidence_requirements is None
    ir = CiscoParser.parse((ROOT / "configs/cisco/compliant.conf").read_text())
    assert ENGINE.evaluate(ir, legacy) == ENGINE.evaluate(ir, CONTROLS[0])


@pytest.mark.parametrize("folder,parser", VENDORS)
@pytest.mark.parametrize("fixture", ["compliant", "noncompliant", "unknown"])
def test_cross_vendor_catalogue_and_new_controls(folder, parser, fixture):
    ir = parser.parse((ROOT / f"configs/{folder}/{fixture}.conf").read_text())
    for control in CONTROLS:
        assert parser.vendor in control.applicable_vendors
        if fixture == "compliant":
            assert all(ir.trace_property(c.path).provenance for c in control.evaluation.conditions)
            assert ENGINE.evaluate(ir, control).result == "PASS"
    for control in CONTROLS[4:]:
        result = ENGINE.evaluate(ir, control)
        assert result.result == {"compliant": "PASS", "noncompliant": "FAIL", "unknown": "UNKNOWN"}[fixture]
        evidence = build_evidence(ir, result)
        assert len(evidence) == 1 and evidence[0].property == control.evaluation.conditions[0].path
        assert evidence == build_evidence(ir, ENGINE.evaluate(ir, control))


@pytest.mark.parametrize("control", CONTROLS)
@pytest.mark.parametrize("mode", ["missing", "ambiguous", "no_provenance"])
def test_requirements_never_manufacture_a_result(control, mode):
    ir = CiscoParser.parse((ROOT / "configs/cisco/compliant.conf").read_text())
    path = control.evaluation.conditions[0].path
    if mode == "missing":
        del ir.normalized_properties[path]
    elif mode == "ambiguous":
        ir.normalized_properties[path] = None
    else:
        del ir.provenance[path]
    result = ENGINE.evaluate(ir, control)
    assert result.result == "UNKNOWN"
    item = next(e for e in build_evidence(ir, result) if e.property == path)
    if mode != "ambiguous":
        assert item.source_file is None and item.line_start is None and item.raw_excerpt is None


@pytest.mark.parametrize("fixture", ["compliant", "noncompliant", "unknown"])
@pytest.mark.parametrize("updates", [
    {"framework_mappings": [{"framework_name": "Synthetic test", "reference_id": "TEST-ONLY"}]},
    {"category": "CRYPTOGRAPHY", "severity": "CRITICAL"},
    {"applicable_vendors": ["astranet"]}, {"remediation_reference": None},
    {"evidence_requirements": None}, {"enabled": False},
])
def test_metadata_cannot_change_evaluation_or_evidence(fixture, updates):
    ir = CiscoParser.parse((ROOT / f"configs/cisco/{fixture}.conf").read_text())
    for control in CONTROLS:
        changed = ControlDefinition.model_validate(control.model_dump() | updates)
        original = ENGINE.evaluate(ir, control)
        assert ENGINE.evaluate(ir, changed) == original
        assert build_evidence(ir, ENGINE.evaluate(ir, changed)) == build_evidence(ir, original)


def test_astranet_does_not_claim_direct_property_support():
    ir = AstraNetParser.parse((ROOT / "configs/astranet/unknown-pattern.conf").read_text())
    assert ir.normalized_properties == {}
    assert all("astranet" not in c.applicable_vendors for c in CONTROLS)
    assert all(r.result == "UNKNOWN" for r in ENGINE.evaluate_all(ir, CONTROLS))


def test_loader_validates_disabled_controls_and_duplicate_ids(tmp_path):
    path = tmp_path / "controls.yaml"
    payload = [c.model_dump(mode="json") for c in CONTROLS]
    payload[0]["enabled"] = False
    payload[4]["enabled"] = False
    payload[5]["enabled"] = False
    path.write_text(yaml.safe_dump({"controls": payload}))
    assert [c.control_id for c in load_demo_controls(path)] == ["CTRL-002", "CTRL-003", "CTRL-004"]
    payload[0]["category"] = "INVALID"
    path.write_text(yaml.safe_dump({"controls": payload}))
    with pytest.raises(CatalogueError) as error:
        load_demo_controls(path)
    assert error.value.error_code == "INVALID_CATALOGUE"
    path.write_text(yaml.safe_dump({"controls": [payload[1], payload[1]]}))
    with pytest.raises(ValueError, match="unique"):
        load_demo_controls(path)
