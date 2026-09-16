"""Independent V2 boundary and regression tests."""
from copy import deepcopy
from io import BytesIO
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pypdf import PdfReader

from app.config import CatalogueError, load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.coverage import coverage_counts
from app.domain.evidence import build_evidence
from app.domain.mapping import MappingVersion, pattern_signature, normalized_context
from app.domain.schemas import ControlDefinition, EvidenceRequirements, AnalysisResponse
from app.domain.security_ir import SecurityIR, DeviceInfo, SourceLocation
from app.main import app
from app.parsers.astranet import AstraNetParser
from app.services.mapping_application_service import MappingApplicationService, MappingApplicationError
from app.storage.database import get_analysis_bundle, get_mapping_versions, initialize_database, reset_demo_database, save_analysis_result

ROOT = Path(__file__).resolve().parents[2]
ENGINE = DeterministicControlEngine()
CONTROLS = {c.control_id: c for c in load_demo_controls()}
SSH = "management.ssh_enabled"
TELNET = "management.telnet_enabled"


def ir(values):
    return SecurityIR(device=DeviceInfo(vendor="cisco_iosxe"), normalized_properties=values,
                      provenance={p: SourceLocation(source_file="test.conf", line_start=1, raw_excerpt="test fixture") for p in values})


@pytest.mark.parametrize("control_id,values,expected", [
    ("CTRL-005", {SSH: True}, "PASS"), ("CTRL-005", {SSH: False}, "FAIL"), ("CTRL-005", {}, "UNKNOWN"),
    ("CTRL-006", {TELNET: False}, "PASS"), ("CTRL-006", {TELNET: True}, "FAIL"), ("CTRL-006", {}, "UNKNOWN"),
    ("CTRL-001", {SSH: True, TELNET: False}, "PASS"),
    ("CTRL-001", {SSH: True, TELNET: True}, "FAIL"),
    ("CTRL-001", {SSH: False, TELNET: False}, "FAIL"),
    ("CTRL-001", {SSH: True}, "UNKNOWN"), ("CTRL-001", {TELNET: True}, "UNKNOWN"),
])
def test_independent_control_semantics(control_id, values, expected):
    assert ENGINE.evaluate(ir(values), CONTROLS[control_id]).result == expected


@pytest.mark.parametrize("control_id,path", [("CTRL-005", SSH), ("CTRL-006", TELNET), ("CTRL-002", "logging.enabled"), ("CTRL-003", "password_protection.enabled"), ("CTRL-004", "time_sync.ntp_enabled")])
@pytest.mark.parametrize("value", [0, 1, 0.0, 1.0, "true", "false", "", [], {}, None])
def test_invalid_actual_types_never_decide_compliance(control_id, path, value):
    source = ir({path: value})
    result = ENGINE.evaluate(source, CONTROLS[control_id])
    assert result.result == "UNKNOWN"
    assert build_evidence(source, result)[0].result == "UNKNOWN"
    assert source.normalized_properties[path] == value


@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_invalid_expectations_are_unknown_even_when_models_are_mutated(value):
    control = CONTROLS["CTRL-005"].model_copy(deep=True)
    control.evaluation.conditions[0].expected = value
    assert ENGINE.evaluate(ir({SSH: True}), control).result == "UNKNOWN"


@pytest.mark.parametrize("metadata", [
    {"category": "CRYPTOGRAPHY"}, {"severity": "LOW"},
    {"framework_mappings": [{"framework_name": "Test only", "reference_id": "TEST"}]},
    {"remediation_reference": None}, {"applicable_vendors": ["astranet"]},
])
def test_metadata_is_not_a_compliance_input(metadata):
    original = CONTROLS["CTRL-001"]
    changed = ControlDefinition.model_validate(original.model_dump() | metadata)
    for values in ({SSH: True, TELNET: False}, {SSH: True, TELNET: True}, {}):
        assert ENGINE.evaluate(ir(values), original) == ENGINE.evaluate(ir(values), changed)


def write_catalogue(tmp_path, document):
    path = tmp_path / "catalogue.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


@pytest.mark.parametrize("document", [None, [], {}, {"controlz": []}, {"controls": None}, {"controls": {}}, {"controls": "bad"}, {"controls": []}, {"controls": [None]}, {"controls": [{}]}])
def test_invalid_envelopes_fail_clearly(tmp_path, document):
    with pytest.raises(CatalogueError) as error:
        load_demo_controls(write_catalogue(tmp_path, document))
    assert error.value.error_code == "INVALID_CATALOGUE" and error.value.detail


@pytest.mark.parametrize("change", [
    {"remediation_reference": {"astranet": "MISSING"}},
    {"remediation_reference": {"cisco_iosxe": "REM-CTRL-001-FORTIGATE"}},
    {"control_id": "CTRL-OTHER", "remediation_reference": {"cisco_iosxe": "REM-CTRL-001-CISCO"}},
    {"remediation_reference": {"invalid": "REM-CTRL-001-CISCO"}},
])
def test_invalid_references_rejected(tmp_path, change):
    payload = CONTROLS["CTRL-001"].model_dump(mode="json") | change
    with pytest.raises(CatalogueError):
        load_demo_controls(write_catalogue(tmp_path, {"controls": [payload]}))


def test_duplicate_ids_and_disabled_catalogue(tmp_path):
    payload = CONTROLS["CTRL-001"].model_dump(mode="json")
    with pytest.raises(CatalogueError, match="unique"):
        load_demo_controls(write_catalogue(tmp_path, {"controls": [payload, payload]}))
    payload["enabled"] = False
    assert load_demo_controls(write_catalogue(tmp_path, {"controls": [payload]})) == []


@pytest.mark.parametrize("parent", ["MISSING", "CTRL-005", "CTRL-006"])
def test_invalid_relationships_fail(tmp_path, parent):
    payload = [c.model_dump(mode="json") for c in CONTROLS.values()]
    payload[4]["diagnostic_of"] = parent
    with pytest.raises(CatalogueError):
        load_demo_controls(write_catalogue(tmp_path, {"controls": payload}))


def test_advisory_evidence_fields_cannot_filter_evidence():
    control = CONTROLS["CTRL-005"].model_copy(deep=True)
    control.evidence_requirements.display_fields = []
    source = ir({SSH: True})
    assert build_evidence(source, ENGINE.evaluate(source, control)) == build_evidence(source, ENGINE.evaluate(source, CONTROLS["CTRL-005"]))
    with pytest.raises(ValidationError):
        EvidenceRequirements(display_fields=["invented"])


def test_bad_yaml_expectations_and_orphan_diagnostics(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("controls: [", encoding="utf-8")
    with pytest.raises(CatalogueError):
        load_demo_controls(path)
    payload = CONTROLS["CTRL-005"].model_dump(mode="json")
    payload["diagnostic_of"] = None
    payload["evaluation"]["conditions"][0]["expected"] = 1
    with pytest.raises(CatalogueError, match="expected type"):
        load_demo_controls(write_catalogue(tmp_path, {"controls": [payload]}))
    payload = [c.model_dump(mode="json") for c in CONTROLS.values()]
    payload[0]["enabled"] = False
    with pytest.raises(CatalogueError, match="enabled parent"):
        load_demo_controls(write_catalogue(tmp_path, {"controls": payload}))


def test_relationship_does_not_change_deterministic_result():
    child = CONTROLS["CTRL-005"]
    independent = child.model_copy(update={"diagnostic_of": None})
    for value in (True, False, None):
        assert ENGINE.evaluate(ir({SSH: value}), child) == ENGINE.evaluate(ir({SSH: value}), independent)


def approved_mapping(source):
    pattern = source.unknown_patterns[0]
    return MappingVersion.model_validate({
        "mapping_id": "test-mapping", "pattern_id": pattern.pattern_id,
        "vendor": source.device.vendor, "pattern_signature": pattern_signature(source.device.vendor, pattern.raw_pattern),
        "approved_mapping": {SSH: True, TELNET: False}, "proposed_mapping": {SSH: True, TELNET: False},
        "status": "APPROVED", "active": True, "version": 1, "reviewer_id": "test", "action": "APPROVE",
        "created_at": "2026-09-14T00:00:00Z", "updated_at": "2026-09-14T00:00:00Z",
        "identity": {"context": normalized_context(pattern), "source_pattern": pattern.raw_pattern,
                     "target_properties": [SSH, TELNET], "source_location": pattern.location.model_dump(), "source_analysis_id": "test-analysis"},
    })


def astranet_ir():
    return AstraNetParser.parse((ROOT / "configs/astranet/unknown-pattern.conf").read_text())


@pytest.mark.parametrize("mismatch", ["signature", "vendor", "context", "properties", "version", "inactive", "rejected", "legacy"])
def test_mapping_identity_mismatch_never_applies(mismatch):
    source = astranet_ir()
    mapping = approved_mapping(source)
    if mismatch == "signature":
        source.unknown_patterns[0].raw_pattern = "guard-channel unrelated"
    elif mismatch == "vendor":
        source.device.vendor = "cisco_iosxe"
    elif mismatch == "context":
        source.unknown_patterns[0].context = "different context"
    elif mismatch == "properties":
        mapping.approved_mapping["logging.enabled"] = True
    elif mismatch == "version":
        mapping.version = 0
    elif mismatch == "inactive":
        mapping.active = False
    elif mismatch == "rejected":
        mapping.status = "REJECTED"
    else:
        mapping.identity = None
    before = source.model_dump()
    with pytest.raises(MappingApplicationError):
        MappingApplicationService().apply(source, mapping)
    assert source.model_dump() == before


def test_matching_identity_can_apply_to_new_occurrence_and_preserves_version():
    source = astranet_ir()
    mapping = approved_mapping(source)
    source.unknown_patterns[0].pattern_id = "different-occurrence"
    before = source.model_dump()
    child = MappingApplicationService().apply(source, mapping, pattern_id="different-occurrence")
    assert child.normalized_properties == {SSH: True, TELNET: False}
    assert child.mapping_provenance[SSH].mapping_version == 1
    assert source.model_dump() == before
    newer = mapping.model_copy(deep=True)
    newer.version = 2
    newer.approved_mapping[SSH] = False
    second = MappingApplicationService().apply(source, newer, pattern_id="different-occurrence")
    assert second.normalized_properties[SSH] is False
    assert child.normalized_properties[SSH] is True


def test_valid_identity_does_not_overwrite_existing_property():
    source = astranet_ir()
    mapping = approved_mapping(source)
    source.normalized_properties[SSH] = False
    with pytest.raises(MappingApplicationError, match="overwrite"):
        MappingApplicationService().apply(source, mapping)
    assert source.normalized_properties[SSH] is False


@pytest.fixture
def client():
    initialize_database()
    reset_demo_database()
    with TestClient(app) as value:
        yield value
    reset_demo_database()


def upload(client, folder="cisco", name="noncompliant.conf"):
    return client.post("/api/analyze", files={"file": (name, (ROOT / "configs" / folder / name).read_bytes(), "text/plain")}).json()


def test_api_pdf_count_roots_and_keep_diagnostics(client):
    payload = upload(client)
    analysis = AnalysisResponse.model_validate(payload)
    assert len(analysis.results) == 6
    assert coverage_counts(analysis.results) == {"FAIL": 4}
    assert {r.control_id: r.diagnostic_of for r in analysis.results if r.diagnostic_of} == {"CTRL-005": "CTRL-001", "CTRL-006": "CTRL-001"}
    assert {e.control_id for e in analysis.evidence} == set(CONTROLS)
    pdf = client.get(f"/api/reports/{analysis.analysis_id}/pdf")
    assert pdf.status_code == 200
    text = "\n".join(p.extract_text() for p in PdfReader(BytesIO(pdf.content)).pages)
    assert "Independent requirement totals" in text and "diagnostic of CTRL-001" in text
    remediation = client.get(f"/api/remediation/{analysis.analysis_id}").json()["remediations"][0]
    sim = client.post(f"/api/remediation/{analysis.analysis_id}/simulate", json={"remediation_id": remediation["remediation_id"]}).json()
    assert sum(r["diagnostic_of"] is None for r in sim["results"]) == 4


def test_reanalysis_rejects_collision_and_preserves_original(client):
    payload = upload(client, "astranet", "unknown-pattern.conf")
    aid = payload["analysis_id"]
    pid = payload["unknown_patterns"][0]["pattern_id"]
    response = client.post(f"/api/mappings/{pid}/approve", json={"reviewer_id": "test", "semantic_mapping": {SSH: True, TELNET: False}})
    assert response.status_code == 200
    saved = get_analysis_bundle(aid)
    child = client.post(f"/api/analyze/{aid}/reanalyze")
    assert child.status_code == 200
    assert coverage_counts(AnalysisResponse.model_validate(child.json()).results) == {"PASS": 1, "UNKNOWN": 3}
    unrelated = deepcopy(saved)
    unrelated["response"]["analysis_id"] = "unrelated"
    for part in (unrelated["response"], unrelated["security_ir"]):
        part["unknown_patterns"][0]["raw_pattern"] = "guard-channel unrelated"
    save_analysis_result(analysis_id="unrelated", filename="other.conf", vendor="astranet", response=unrelated["response"], security_ir=unrelated["security_ir"])
    blocked = client.post("/api/analyze/unrelated/reanalyze")
    assert blocked.status_code == 409 and blocked.json()["error_code"] == "INVALID_MAPPING"
    review = client.post(f"/api/mappings/{pid}/suggest")
    assert review.status_code == 409 and review.json()["error_code"] == "INVALID_MAPPING"
    assert get_analysis_bundle(aid) == saved
    assert len(get_mapping_versions(pid)) == 1


def test_configuration_occurrences_do_not_collide(client):
    original = upload(client, "astranet", "unknown-pattern.conf")
    content = (ROOT / "configs/astranet/unknown-pattern.conf").read_text().replace("lattice-secure", "unrelated")
    other = client.post("/api/analyze", files={"file": ("other.conf", content.encode(), "text/plain")}).json()
    first_id = original["unknown_patterns"][0]["pattern_id"]
    second_id = other["unknown_patterns"][0]["pattern_id"]
    assert first_id != second_id
    assert original["unknown_patterns"][0]["line_start"] == other["unknown_patterns"][0]["line_start"]
    assert client.post(f"/api/mappings/{first_id}/suggest").status_code == 200
    assert client.post(f"/api/analyze/{other['analysis_id']}/reanalyze").status_code == 409


def test_catalogue_api_error_is_structured(client, monkeypatch):
    def invalid():
        raise CatalogueError("Test malformed catalogue")
    monkeypatch.setattr("app.api.analyze.load_demo_controls", invalid)
    response = client.post("/api/analyze", files={"file": ("valid.conf", b"hostname test", "text/plain")})
    assert response.status_code == 500
    assert response.json() == {"error_code": "INVALID_CATALOGUE", "detail": "Test malformed catalogue"}


def test_old_mapping_versions_remain_reportable_after_correction(client):
    original = upload(client, "astranet", "unknown-pattern.conf")
    pid = original["unknown_patterns"][0]["pattern_id"]
    def approve(ssh):
        response = client.post(f"/api/mappings/{pid}/approve", json={"reviewer_id": "test", "semantic_mapping": {SSH: ssh, TELNET: False}})
        assert response.status_code == 200
        return response.json()["mapping"]
    first = approve(True)
    child = client.post(f"/api/analyze/{original['analysis_id']}/reanalyze").json()
    before = get_analysis_bundle(child["analysis_id"])
    second = approve(False)
    history = get_mapping_versions(pid)
    assert first["version"] == 1 and second["version"] == 2
    assert history[0]["identity"] == first["identity"]
    assert history[0]["approved_mapping"] == {SSH: True, TELNET: False}
    assert history[0]["active"] is False
    assert get_analysis_bundle(child["analysis_id"]) == before
    assert client.get(f"/api/reports/{child['analysis_id']}/pdf").status_code == 200
