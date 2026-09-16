from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.evidence import build_evidence
from app.domain.mapping import CandidateMappingSuggestion
from app.domain.properties import parser_capability, valid_property_value, PROPERTY_DEFINITIONS
from app.domain.schemas import ControlDefinition
from app.parsers.cisco import CiscoParser
from app.parsers.fortigate import FortiGateParser
from app.parsers.paloalto import PaloAltoParser
from app.storage.database import reset_demo_database, get_analysis_bundle, get_connection, save_analysis_result
from app.services.inventory_service import prepare_inventory

ROOT = Path(__file__).resolve().parents[2]
CASES = [("cisco", CiscoParser, "logging.buffered_enabled"), ("fortigate", FortiGateParser, "credentials.password_policy_enabled"), ("paloalto", PaloAltoParser, "credentials.username_exclusion_enabled")]


@pytest.fixture
def client():
    reset_demo_database()
    with TestClient(app) as value:
        yield value
    reset_demo_database()


def upload(client, folder="cisco", name="compliant.conf", device_id=None):
    data = {"device_id": device_id} if device_id else {}
    return client.post("/api/analyze", files={"file": (name, (ROOT / "configs" / folder / name).read_bytes(), "text/plain")}, data=data)


def test_device_configuration_and_analysis_creation(client):
    response = upload(client)
    assert response.status_code == 200
    analysis = response.json()
    config = analysis["configuration"]
    device = client.get(f"/api/devices/{config['device_id']}").json()
    assert analysis["device"]["device_id"] == device["device_id"]
    assert device["hostname"] == "demo-cisco-compliant" and device["software_version"] == "17.9"
    assert device["serial_number"] is None and device["platform"] is None
    assert device["created_at"] == device["updated_at"]
    assert device["metadata_provenance"]["hostname"]["source_file"] == "compliant.conf"
    assert config["source_filename"] == "compliant.conf" and config["detected_vendor"] == "cisco_iosxe"
    assert config["content_sha256"] == sha256((ROOT / "configs/cisco/compliant.conf").read_bytes()).hexdigest()
    history = client.get(f"/api/configurations/{config['configuration_id']}").json()
    assert history["analysis_ids"] == [analysis["analysis_id"]]
    assert client.get(f"/api/devices/{device['device_id']}/analyses").json()["analysis_ids"] == [analysis["analysis_id"]]
    assert get_analysis_bundle(analysis["analysis_id"])["security_ir"]["device"]["device_id"] == device["device_id"]


def test_duplicates_preserve_uploads_and_do_not_guess_device_identity(client):
    first, second = upload(client).json(), upload(client).json()
    a, b = first["configuration"], second["configuration"]
    assert a["content_sha256"] == b["content_sha256"]
    assert a["configuration_id"] != b["configuration_id"] and a["device_id"] == b["device_id"]
    assert b["duplicate_of_configuration_id"] == a["configuration_id"]
    assert client.get(f"/api/configurations/{a['configuration_id']}").json()["analysis_ids"] == [first["analysis_id"]]


def test_explicit_device_association_and_vendor_validation(client):
    first = upload(client).json()
    did = first["device"]["device_id"]
    second = upload(client, name="noncompliant.conf", device_id=did)
    assert second.status_code == 200
    assert second.json()["configuration"]["device_id"] == did
    assert get_analysis_bundle(first["analysis_id"])["response"] == first
    assert upload(client, folder="fortigate", device_id=did).status_code == 400
    missing = upload(client, device_id="missing")
    assert missing.status_code == 404 and missing.json()["error_code"] == "DEVICE_NOT_FOUND"


def test_missing_metadata_and_failed_upload(client):
    result = client.post("/api/analyze", files={"file": ("minimal.conf", b"line vty 0 4\n transport input ssh", "text/plain")})
    assert result.status_code == 200
    device = client.get(f"/api/devices/{result.json()['device']['device_id']}").json()
    assert device["hostname"] is None and device["serial_number"] is None and device["software_version"] is None
    assert device["metadata_provenance"] == {}
    bad = client.post("/api/analyze", files={"file": ("bad.conf", b"", "text/plain")})
    assert bad.status_code == 400
    assert client.get("/api/configurations/missing").status_code == 404


def test_reanalysis_links_same_configuration_and_preserves_original(client):
    original = upload(client, "astranet", "unknown-pattern.conf").json()
    pid = original["unknown_patterns"][0]["pattern_id"]
    approved = client.post(f"/api/mappings/{pid}/approve", json={"reviewer_id": "test", "semantic_mapping": {"management.ssh_enabled": True, "management.telnet_enabled": False}})
    assert approved.status_code == 200
    before = get_analysis_bundle(original["analysis_id"])
    child = client.post(f"/api/analyze/{original['analysis_id']}/reanalyze")
    assert child.status_code == 200
    assert child.json()["configuration"] == original["configuration"]
    history = client.get(f"/api/configurations/{original['configuration']['configuration_id']}").json()
    assert history["analysis_ids"] == [original["analysis_id"], child.json()["analysis_id"]]
    assert get_analysis_bundle(original["analysis_id"]) == before
    assert original["configuration"]["parser_status"] == "PARTIAL"


@pytest.mark.parametrize("folder,parser,path", CASES)
@pytest.mark.parametrize("fixture,value", [("compliant", True), ("noncompliant", False)])
def test_new_properties_have_exact_values_types_and_provenance(folder, parser, path, fixture, value):
    source = parser.parse((ROOT / f"configs/{folder}/{fixture}.conf").read_text(), source_file="input.conf")
    assert source.normalized_properties[path] is value
    trace = source.trace_property(path)
    assert trace.provenance.source_file == "input.conf" and trace.provenance.line_start >= 1
    assert trace.provenance.raw_excerpt
    assert parser_capability(path, parser.vendor) == "SUPPORTED"
    assert valid_property_value(path, value)
    control = ControlDefinition(control_id="TEST", name="Test", description="Test", expected_value="true", evaluation={"type": "equals", "conditions": [{"path": path, "operator": "equals", "expected": True}]})
    result = DeterministicControlEngine().evaluate(source, control)
    assert result.result == ("PASS" if value else "FAIL")
    assert build_evidence(source, result)[0].raw_excerpt == trace.provenance.raw_excerpt
    assert len(DeterministicControlEngine().evaluate_all(source, load_demo_controls())) == 6


@pytest.mark.parametrize("folder,parser,path", CASES)
@pytest.mark.parametrize("invalid", [1, 0, "true", None])
def test_new_property_types_are_strict(folder, parser, path, invalid):
    assert not valid_property_value(path, invalid)


def test_capabilities_do_not_fabricate_support_or_expand_mapping_scope(client):
    capabilities = client.get("/api/parser-capabilities").json()
    assert capabilities["logging.enabled"]["vendors"]["cisco_iosxe"] == "PARTIAL"
    for folder, parser, path in CASES:
        assert parser_capability(path, "astranet") == "UNSUPPORTED"
        for other_folder, other_parser, other_path in CASES:
            if other_path != path:
                assert parser_capability(path, other_parser.vendor) == "UNSUPPORTED"
                source = other_parser.parse((ROOT / f"configs/{other_folder}/compliant.conf").read_text())
                assert path not in source.normalized_properties
        assert PROPERTY_DEFINITIONS[path].description and PROPERTY_DEFINITIONS[path].provenance_expectation
        with pytest.raises(ValueError):
            CandidateMappingSuggestion(pattern_id="test", confidence=0.9, reasoning="test", semantic_mapping={path: True})
    assert parser_capability("invented.property", "cisco_iosxe") == "UNSUPPORTED"


def test_platform_is_only_populated_from_header(client):
    payload = upload(client, "fortigate").json()
    device = client.get(f"/api/devices/{payload['device']['device_id']}").json()
    assert device["platform"] == "FGT60F"
    assert "#config-version=FGT60F" in device["metadata_provenance"]["platform"]["raw_excerpt"]
    assert device["serial_number"] is None


def test_atomic_persistence_rolls_back_inventory_on_analysis_failure(client):
    first = upload(client).json()
    source = CiscoParser.parse("hostname test")
    device, config = prepare_inventory(source, "test.conf", "a" * 64)
    with pytest.raises(Exception):
        save_analysis_result(analysis_id=first["analysis_id"], filename="test.conf", vendor="cisco_iosxe", response={}, device_record=device, configuration_record=config)
    assert client.get(f"/api/devices/{device.device_id}").status_code == 404
    assert client.get(f"/api/configurations/{config.configuration_id}").status_code == 404


def test_demo_reset_clears_new_records(client):
    result = upload(client).json()
    assert client.post("/api/demo/reset").status_code == 200
    assert client.get(f"/api/devices/{result['device']['device_id']}").status_code == 404
    assert client.get(f"/api/configurations/{result['configuration']['configuration_id']}").status_code == 404
