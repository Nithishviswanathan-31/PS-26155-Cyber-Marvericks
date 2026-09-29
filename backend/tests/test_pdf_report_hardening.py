from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app.domain.enums import ComplianceResult
from app.domain.schemas import (
    AnalysisDeviceResponse,
    AnalysisResponse,
    ControlResultSummary,
    EvidenceRecord,
)
from app.main import app
from app.services.report_service import generate_analysis_pdf
from app.storage.database import get_analysis_bundle, get_connection, initialize_database


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def isolate_report_records() -> None:
    initialize_database()
    connection = get_connection()
    try:
        for table in (
            "simulation_results",
            "mapping_approvals",
            "mapping_versions",
            "mappings",
            "analysis_results",
            "reports",
        ):
            connection.execute(f"DELETE FROM {table}")
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _upload(client: TestClient, directory: str, filename: str) -> dict:
    path = ROOT / "configs" / directory / filename
    response = client.post("/api/analyze", files={"file": (filename, path.read_bytes(), "text/plain")})
    assert response.status_code == 200
    return response.json()


def _upload_fixture(client: TestClient, relative_path: str) -> dict:
    path = ROOT / relative_path
    response = client.post("/api/analyze", files={"file": (path.name, path.read_bytes(), "text/plain")})
    assert response.status_code == 200
    return response.json()


def _pdf_text(content: bytes) -> str:
    reader = PdfReader(BytesIO(content))
    assert reader.pages
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# 1. Cisco Non-compliant Report
def test_01_cisco_noncompliant_report(client: TestClient) -> None:
    analysis = _upload(client, "cisco", "noncompliant.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pdf")

    text = _pdf_text(resp.content)
    # Header & Device Identity
    assert "demo-cisco-noncompliant" in text
    assert "cisco_iosxe" in text
    assert "17.9" in text

    # Executive Summary & Results
    assert "Executive Summary" in text
    assert "Control Results" in text
    assert "FAIL" in text
    assert "CTRL-001" in text

    # Step-by-Step Remediation Guidance
    assert "Device-Specific CLI Remediation Guidance" in text
    assert "Enable SSH and disable Telnet" in text
    assert "Step 1: Enter global configuration mode: configure terminal" in text
    assert "transport input ssh" in text
    assert "SIMULATION ONLY" in text
    assert "No production device was contacted or modified" in text

    # Integrity
    assert "Cryptographic Integrity Ledger Audit" in text
    assert "VALID" in text


# 2. FortiGate Compliant Report
def test_02_fortigate_compliant_report(client: TestClient) -> None:
    analysis = _upload(client, "fortigate", "compliant.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    # Device Identification
    assert "demo-fortigate-compliant" in text
    assert "fortigate_fortios" in text
    assert "7.4.3" in text
    assert "FGT60F" in text
    assert "Not present in configuration" in text  # serial number absent

    # Results & Framework Cross-references
    assert "PASS" in text
    assert "Multi-Framework Cross-References (Advisory)" in text
    assert "CIS Controls v8" in text
    assert "NIST SP 800-53" in text

    # All compliant notice
    assert "All evaluated controls passed or are compliant" in text


# 3. Palo Alto Mixed Report
def test_03_paloalto_mixed_report(client: TestClient) -> None:
    analysis = _upload(client, "paloalto", "mixed.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    assert "demo-paloalto-mixed" in text
    assert "paloalto_panos" in text

    # Shows both PASS and FAIL
    assert "PASS" in text
    assert "FAIL" in text

    # Step-by-step remediation for failing controls
    assert "Device-Specific CLI Remediation Guidance" in text
    assert "Note on Parameter Placeholders" in text


# 4. AstraNet Original Unknown Report
def test_04_astranet_original_unknown_report(client: TestClient) -> None:
    analysis = _upload(client, "astranet", "unknown-pattern.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    assert "demo-astranet-unknown" in text
    assert "astranet" in text
    assert "UNKNOWN" in text

    # Analysis Lineage shows Re-analysis: NO
    assert "Analysis Lineage" in text
    assert "Re-analysis" in text
    assert "NO" in text

    # Adaptive Mapping section must NOT appear on original unresolved analysis
    assert "6. Adaptive Mapping" not in text


# 5. AstraNet Reanalyzed Report
def test_05_astranet_reanalyzed_report(client: TestClient) -> None:
    original = _upload(client, "astranet", "unknown-pattern.conf")
    pattern_id = original["unknown_patterns"][0]["pattern_id"]

    # Suggest and approve
    suggestion = client.post(f"/api/mappings/{pattern_id}/suggest").json()
    approved = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "auditor-charlie", "semantic_mapping": suggestion["semantic_mapping"]},
    )
    assert approved.status_code == 200

    # Re-analyze
    child = client.post(f"/api/analyze/{original['analysis_id']}/reanalyze").json()

    # Generate PDF for reanalyzed child
    resp = client.get(f"/api/reports/{child['analysis_id']}/pdf")
    assert resp.status_code == 200
    text = _pdf_text(resp.content)

    # Adaptive Mapping section is present
    assert "Adaptive Mapping" in text
    assert "guard-channel lattice-secure" in text
    assert "RECOGNIZED_VIA_APPROVED_MAPPING" in text
    assert "Human approved" in text
    assert "auditor-charlie" in text

    # Control results evaluate to PASS
    assert "PASS" in text
    assert "APPROVED_MAPPING" in text


# 6. Device with Model and Serial Present
def test_06_device_with_model_and_serial_present(client: TestClient) -> None:
    analysis = _upload_fixture(client, "configs/fixtures/cisco_with_device_id.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    # Explicitly contains extracted values
    assert "edge-router-01" in text
    assert "ISR4431/K9" in text
    assert "FGL193820ZZ" in text
    assert "889a1313" in text


# 7. Device with Model and Serial Absent
def test_07_device_with_model_and_serial_absent(client: TestClient) -> None:
    analysis = _upload(client, "cisco", "compliant.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    # Hardware model and serial number absent -> rendered without fabrication
    assert "Not present in configuration" in text


# 8. Remediation Simulation Report
def test_08_remediation_simulation_report(client: TestClient) -> None:
    analysis = _upload(client, "cisco", "noncompliant.conf")
    remediations = client.get(f"/api/remediation/{analysis['analysis_id']}").json()["remediations"]
    rem_id = remediations[0]["remediation_id"]

    sim_resp = client.post(
        f"/api/remediation/{analysis['analysis_id']}/simulate",
        json={"remediation_id": rem_id},
    )
    assert sim_resp.status_code == 200

    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200
    text = _pdf_text(resp.content)

    assert "Remediation Simulation" in text
    assert "Before Result" in text
    assert "FAIL" in text
    assert "After Result" in text
    assert "PASS" in text
    assert "SIMULATED_REMEDIATION" in text
    assert "SIMULATION ONLY" in text
    assert "No production device was contacted or modified" in text


# 9. Multi-Framework Cross-References Table
def test_09_multi_framework_cross_references_table(client: TestClient) -> None:
    analysis = _upload(client, "fortigate", "compliant.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    assert "Multi-Framework Cross-References (Advisory)" in text
    assert "CIS Controls v8" in text
    assert "NIST SP 800-53" in text
    assert "DISA STIG" in text
    assert "ISO/IEC 27001:2022" in text
    assert "VERIFIED" in text
    assert "Advisory Traceability Disclaimer" in text


# 10. Severity Breakdown and Result Counts
def test_10_severity_breakdown_and_result_counts(client: TestClient) -> None:
    analysis = _upload(client, "cisco", "compliant.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    assert "Compliance Evaluation Summary" in text
    assert "PASS" in text
    assert "Severity Distribution of Evaluated Controls" in text
    assert "CRITICAL" in text
    assert "HIGH" in text
    assert "MEDIUM" in text
    assert "LOW" in text


# 11. Evidence Source Distinction
def test_11_evidence_source_distinction(client: TestClient) -> None:
    analysis = _upload(client, "cisco", "compliant.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    assert "Evidence Details" in text
    assert "Evidence Source" in text
    assert "CONFIGURATION" in text


# 12. Cryptographic Integrity Ledger Audit
def test_12_cryptographic_integrity_ledger_audit(client: TestClient) -> None:
    analysis = _upload(client, "cisco", "compliant.conf")
    resp = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp.status_code == 200

    text = _pdf_text(resp.content)
    assert "Cryptographic Integrity Ledger Audit" in text
    assert "Analysis Content SHA-256" in text
    assert "Report Ledger Record ID" in text
    assert "SHA-256 Append-Only Tamper-Evident Ledger" in text


# 13. Original Analysis Immutability
def test_13_original_analysis_immutability(client: TestClient) -> None:
    analysis = _upload(client, "cisco", "noncompliant.conf")
    before_bundle = get_analysis_bundle(analysis["analysis_id"])

    # Generate report multiple times
    client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    client.get(f"/api/reports/{analysis['analysis_id']}/pdf")

    after_bundle = get_analysis_bundle(analysis["analysis_id"])
    assert after_bundle == before_bundle


# 14. Legacy Analysis Compatibility (Missing Phase 1/2 metadata)
def test_14_legacy_analysis_compatibility() -> None:
    # Construct an analysis model that lacks Phase 1/2 metadata
    legacy_analysis = AnalysisResponse(
        analysis_id=str(uuid4()),
        filename="legacy.conf",
        vendor="cisco_iosxe",
        device=AnalysisDeviceResponse(
            hostname="legacy-cisco",
            version=None,
            device_model=None,
            serial_number=None,
            device_id=None,
            platform=None,
        ),
        results=[
            ControlResultSummary(
                control_id="CTRL-001",
                control_name="Legacy Control",
                result=ComplianceResult.UNKNOWN,
                expected=True,
                actual=None,
                explanation="Legacy control explanation",
                severity=None,
                category=None,
                framework_mappings=[],
            )
        ],
        evidence=[],
    )

    # Must generate cleanly without errors
    pdf_bytes = generate_analysis_pdf(
        legacy_analysis,
        report_id=f"report-{uuid4().hex[:12]}",
        generated_at="2026-09-29T12:00:00Z",
    )
    assert pdf_bytes.startswith(b"%PDF-1.4")
    text = _pdf_text(pdf_bytes)
    assert "legacy-cisco" in text
    assert "Not present in configuration" in text
    assert "CTRL-001" in text
    assert "UNKNOWN" in text


# 15. Report History and ID Consistency
def test_15_report_history_and_id_consistency(client: TestClient) -> None:
    analysis = _upload(client, "cisco", "compliant.conf")

    # First PDF generation -> version 1
    resp1 = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp1.status_code == 200

    # Second PDF generation -> version 2
    resp2 = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert resp2.status_code == 200

    history = client.get(f"/api/reports/{analysis['analysis_id']}").json()
    items = history["items"]
    assert len(items) == 2
    assert items[0]["report_version"] == 2
    assert items[1]["report_version"] == 1

    # Report ID in history is found in generated PDF
    text1 = _pdf_text(resp1.content)
    assert items[1]["report_id"] in text1
