"""Phase 1 tests for multi-framework compliance foundation.

Validates framework registry, models, catalogue mappings, deterministic
metadata propagation, API endpoints, and backward compatibility.
"""
from io import BytesIO
from pathlib import Path
from typing import Any
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pypdf import PdfReader

from app.config import load_demo_controls
from app.domain.control_engine import DeterministicControlEngine
from app.domain.frameworks import (
    FRAMEWORK_REGISTRY,
    FrameworkInfo,
    get_framework_info,
    get_framework_registry,
)
from app.domain.schemas import (
    AnalysisResponse,
    ControlDefinition,
    ControlEvaluationResult,
    ControlResultSummary,
    FrameworkMapping,
)
from app.domain.security_ir import DeviceInfo, SecurityIR, SourceLocation
from app.main import app
from app.storage.database import (
    get_analysis_bundle,
    get_connection,
    initialize_database,
    reset_demo_database,
    save_analysis_result,
)

ROOT = Path(__file__).resolve().parents[2]
CONTROLS = load_demo_controls()
ENGINE = DeterministicControlEngine()


@pytest.fixture
def client() -> TestClient:
    initialize_database()
    reset_demo_database()
    with TestClient(app) as test_client:
        yield test_client
    reset_demo_database()


def sample_ir() -> SecurityIR:
    return SecurityIR(
        device=DeviceInfo(vendor="cisco_iosxe", hostname="test-switch"),
        normalized_properties={
            "management.ssh_enabled": True,
            "management.telnet_enabled": False,
            "logging.enabled": True,
            "password_protection.enabled": True,
            "time_sync.ntp_enabled": True,
        },
        provenance={
            "management.ssh_enabled": SourceLocation(source_file="test.conf", line_start=1, raw_excerpt="ip ssh version 2"),
            "management.telnet_enabled": SourceLocation(source_file="test.conf", line_start=2, raw_excerpt="transport input ssh"),
            "logging.enabled": SourceLocation(source_file="test.conf", line_start=3, raw_excerpt="logging buffered 16384"),
            "password_protection.enabled": SourceLocation(source_file="test.conf", line_start=4, raw_excerpt="service password-encryption"),
            "time_sync.ntp_enabled": SourceLocation(source_file="test.conf", line_start=5, raw_excerpt="ntp server 10.0.0.1"),
        },
    )


# =========================================================================
# 1. Framework Registry & Service Tests
# =========================================================================

def test_framework_registry_contains_required_frameworks():
    registry = get_framework_registry()
    framework_ids = {f.framework_id for f in registry}
    assert {"CIS", "NIST_SP_800_53", "DISA_STIG", "ISO_27001"} <= framework_ids
    assert len(registry) == 4


def test_framework_registry_metadata_and_verification_status():
    cis = get_framework_info("CIS")
    assert cis is not None
    assert cis.framework_id == "CIS"
    assert cis.version == "v8"
    assert cis.verification_status == "SUPPORTED"
    assert "Center for Internet Security" in cis.description

    nist = get_framework_info("NIST_SP_800_53")
    assert nist is not None
    assert nist.framework_id == "NIST_SP_800_53"
    assert nist.version == "Rev. 5"
    assert nist.verification_status == "SUPPORTED"

    disa = get_framework_info("DISA_STIG")
    assert disa is not None
    assert disa.framework_id == "DISA_STIG"
    assert disa.version == "Network Device STIG"
    assert disa.verification_status == "PROTOTYPE"
    assert "prototype" in disa.description.lower()

    iso = get_framework_info("ISO_27001")
    assert iso is not None
    assert iso.framework_id == "ISO_27001"
    assert iso.version == "2022"
    assert iso.verification_status == "SUPPORTED"


def test_unknown_framework_lookup_returns_none():
    assert get_framework_info("UNKNOWN_FRAMEWORK") is None
    assert get_framework_info("") is None


# =========================================================================
# 2. Framework API Tests
# =========================================================================

def test_api_list_frameworks(client: TestClient):
    response = client.get("/api/frameworks")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 4
    ids = [item["framework_id"] for item in data]
    assert "CIS" in ids
    assert "NIST_SP_800_53" in ids
    assert "DISA_STIG" in ids
    assert "ISO_27001" in ids


def test_api_get_specific_framework(client: TestClient):
    response = client.get("/api/frameworks/CIS")
    assert response.status_code == 200
    data = response.json()
    assert data["framework_id"] == "CIS"
    assert data["version"] == "v8"
    assert data["verification_status"] == "SUPPORTED"


def test_api_get_unknown_framework_returns_404(client: TestClient):
    response = client.get("/api/frameworks/NONEXISTENT")
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "VALIDATION_ERROR"
    assert "not found" in data["detail"].lower()


# =========================================================================
# 3. Model Validation & Constraints
# =========================================================================

def test_framework_mapping_model_valid():
    mapping = FrameworkMapping(
        framework_name="CIS",
        framework_version="v8",
        reference_id="4.2",
        title="Network Infrastructure",
        description="Secure configuration process",
        mapping_status="VERIFIED",
    )
    assert mapping.framework_name == "CIS"
    assert mapping.framework_version == "v8"
    assert mapping.reference_id == "4.2"
    assert mapping.mapping_status == "VERIFIED"


def test_framework_mapping_model_prototype_status():
    mapping = FrameworkMapping(
        framework_name="DISA_STIG",
        framework_version="Network Device STIG",
        reference_id="STIG-NET-MGT-001-PROTO",
        title="Management Session Security",
        description="Prototype STIG reference",
        mapping_status="PROTOTYPE",
    )
    assert mapping.mapping_status == "PROTOTYPE"


def test_framework_mapping_model_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        FrameworkMapping(
            framework_name="CIS",
            reference_id="4.2",
            invented_field="illegal",
        )


def test_framework_mapping_model_blank_fields_rejected():
    with pytest.raises(ValidationError):
        FrameworkMapping(framework_name="   ", reference_id="4.2")
    with pytest.raises(ValidationError):
        FrameworkMapping(framework_name="CIS", reference_id="   ")


def test_framework_info_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        FrameworkInfo(
            framework_id="CIS",
            display_name="CIS",
            version="v8",
            description="desc",
            extra="not_allowed",
        )


# =========================================================================
# 4. Catalogue Framework Mapping Quality & Semantic Verification
# =========================================================================

def test_catalogue_all_controls_have_semantically_appropriate_mappings():
    for control in CONTROLS:
        assert isinstance(control.framework_mappings, list)
        assert len(control.framework_mappings) > 0, f"{control.control_id} has no framework mappings"
        for mapping in control.framework_mappings:
            assert mapping.framework_name in {"CIS", "NIST_SP_800_53", "DISA_STIG", "ISO_27001"}
            assert mapping.reference_id and mapping.reference_id.strip()
            assert mapping.mapping_status in {"VERIFIED", "PROTOTYPE", "INTERNAL"}


def test_catalogue_disa_stig_mappings_are_explicitly_prototype():
    disa_mappings = [
        (control.control_id, mapping)
        for control in CONTROLS
        for mapping in control.framework_mappings
        if mapping.framework_name == "DISA_STIG"
    ]
    assert len(disa_mappings) > 0
    for cid, mapping in disa_mappings:
        assert mapping.mapping_status == "PROTOTYPE", f"{cid} DISA STIG mapping must be PROTOTYPE"
        assert "PROTO" in mapping.reference_id
        assert "(Prototype)" in (mapping.title or "")


def test_catalogue_iso_27001_mappings_semantic_appropriateness():
    iso_mappings = {
        control.control_id: [m.reference_id for m in control.framework_mappings if m.framework_name == "ISO_27001"]
        for control in CONTROLS
    }
    # Secret protection must map to A.5.17 (Authentication information), NOT blindly to A.8.24 (Cryptography)
    assert "A.5.17" in iso_mappings["CTRL-003"]
    assert "A.8.24" not in iso_mappings["CTRL-003"]
    # Logging must map to A.8.15
    assert "A.8.15" in iso_mappings["CTRL-002"]
    # Time sync must map to A.8.17
    assert "A.8.17" in iso_mappings["CTRL-004"]
    # Management access must map to A.8.20
    assert "A.8.20" in iso_mappings["CTRL-001"]


# =========================================================================
# 5. Metadata Propagation & Deterministic Evaluation Invariant
# =========================================================================

def test_engine_evaluates_and_propagates_metadata():
    ir = sample_ir()
    for control in CONTROLS:
        result = ENGINE.evaluate(ir, control)
        assert isinstance(result, ControlEvaluationResult)
        assert result.severity == control.severity
        assert result.category == control.category
        assert result.framework_mappings == control.framework_mappings


def test_deterministic_engine_result_invariant_under_metadata_modification():
    ir = sample_ir()
    original_control = CONTROLS[0]
    base_result = ENGINE.evaluate(ir, original_control)

    # Modifying severity, category, or framework_mappings must not change compliance decision
    modified_control = ControlDefinition.model_validate(
        original_control.model_dump() | {
            "severity": "LOW",
            "category": "CREDENTIAL_PROTECTION",
            "framework_mappings": [],
        }
    )
    new_result = ENGINE.evaluate(ir, modified_control)

    assert base_result.result == new_result.result
    assert base_result.expected == new_result.expected
    assert base_result.actual == new_result.actual
    assert base_result.evidence == new_result.evidence
    assert base_result.explanation == new_result.explanation


# =========================================================================
# 6. Analysis and Reanalysis API Response Metadata
# =========================================================================

def test_analysis_endpoint_propagates_metadata_in_results(client: TestClient):
    conf_bytes = (ROOT / "configs" / "cisco" / "compliant.conf").read_bytes()
    response = client.post("/api/analyze", files={"file": ("compliant.conf", conf_bytes, "text/plain")})
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert len(data["results"]) == len(CONTROLS)

    for result_summary in data["results"]:
        assert "severity" in result_summary
        assert result_summary["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert "category" in result_summary
        assert result_summary["category"] is not None
        assert "framework_mappings" in result_summary
        assert isinstance(result_summary["framework_mappings"], list)
        assert len(result_summary["framework_mappings"]) > 0

        # Verify mapping shape in JSON response
        first_mapping = result_summary["framework_mappings"][0]
        assert "framework_name" in first_mapping
        assert "reference_id" in first_mapping
        assert "mapping_status" in first_mapping


def test_reanalysis_endpoint_preserves_metadata_in_results(client: TestClient):
    astranet_bytes = (ROOT / "configs" / "astranet" / "unknown-pattern.conf").read_bytes()
    orig_resp = client.post("/api/analyze", files={"file": ("unknown-pattern.conf", astranet_bytes, "text/plain")})
    assert orig_resp.status_code == 200
    orig = orig_resp.json()
    pattern_id = orig["unknown_patterns"][0]["pattern_id"]

    suggestion = client.post(f"/api/mappings/{pattern_id}/suggest").json()
    approved = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "phase1-reviewer", "semantic_mapping": suggestion["semantic_mapping"]},
    )
    assert approved.status_code == 200

    reanalyzed = client.post(f"/api/analyze/{orig['analysis_id']}/reanalyze")
    assert reanalyzed.status_code == 200
    reanalyzed_data = reanalyzed.json()

    for result in reanalyzed_data["results"]:
        assert result["severity"] is not None
        assert result["category"] is not None
        assert isinstance(result["framework_mappings"], list)
        assert len(result["framework_mappings"]) > 0


# =========================================================================
# 7. Backward Compatibility: Deserialization of Legacy Stored Analyses
# =========================================================================

def test_backward_compatibility_deserializes_legacy_analysis_without_framework_fields():
    # Simulate a stored V2 JSON record lacking severity, category, and framework_mappings
    legacy_summary = {
        "control_id": "CTRL-001",
        "control_name": "Secure management transport",
        "result": "PASS",
        "expected": "SSH enabled and Telnet disabled",
        "actual": {"management.ssh_enabled": True, "management.telnet_enabled": False},
        "explanation": "All required deterministic conditions are satisfied.",
        "diagnostic_of": None,
    }
    summary = ControlResultSummary.model_validate(legacy_summary)
    assert summary.severity is None
    assert summary.category is None
    assert summary.framework_mappings == []

    legacy_analysis = {
        "analysis_id": "legacy-test-uuid",
        "filename": "legacy.conf",
        "vendor": "cisco_iosxe",
        "device": {
            "hostname": "legacy-host",
            "version": "17.3",
            "device_model": "C9300",
            "platform": "cisco_iosxe",
            "serial_number": "SN123",
            "device_id": "dev-legacy",
        },
        "configuration": None,
        "results": [legacy_summary],
        "evidence": [],
        "unknown_patterns": [],
    }
    analysis = AnalysisResponse.model_validate(legacy_analysis)
    assert analysis.results[0].severity is None
    assert analysis.results[0].category is None
    assert analysis.results[0].framework_mappings == []


def test_backward_compatibility_control_evaluation_result_defaults():
    res = ControlEvaluationResult(
        control_id="CTRL-TEST",
        control_name="Test Control",
        result="PASS",
        expected=True,
        actual=True,
        evidence=[],
        explanation="Test explanation",
    )
    assert res.severity is None
    assert res.category is None
    assert res.framework_mappings == []


# =========================================================================
# 8. Report PDF Includes Framework Cross-References and Severity
# =========================================================================

def test_pdf_report_contains_severity_and_framework_cross_references(client: TestClient):
    conf_bytes = (ROOT / "configs" / "cisco" / "compliant.conf").read_bytes()
    analysis = client.post("/api/analyze", files={"file": ("compliant.conf", conf_bytes, "text/plain")}).json()
    pdf_resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert pdf_resp.status_code == 200
    reader = PdfReader(BytesIO(pdf_resp.content))
    text = "\n".join(p.extract_text() for p in reader.pages)

    # Check for Severity column header and values
    assert "Severity" in text
    assert "HIGH" in text
    assert "MEDIUM" in text

    # Check for Framework Cross-References section
    assert "Framework Cross-References (Advisory)" in text
    assert "CIS v8" in text
    assert "NIST_SP_800_53" in text
    assert "DISA_STIG" in text
    assert "ISO_27001" in text
    assert "VERIFIED" in text
    assert "PROTOTYPE" in text
