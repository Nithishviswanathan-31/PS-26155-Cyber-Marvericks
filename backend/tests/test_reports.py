from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app.main import app
from app.storage.database import get_analysis_bundle, get_connection, initialize_database


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def isolate_report_records() -> None:
    initialize_database()
    connection = get_connection()
    try:
        for table in ("simulation_results", "mapping_approvals", "mapping_versions", "mappings", "analysis_results"):
            connection.execute(f"DELETE FROM {table}")
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def upload(client: TestClient, directory: str, filename: str) -> dict:
    path = ROOT / "configs" / directory / filename
    response = client.post("/api/analyze", files={"file": (filename, path.read_bytes(), "text/plain")})
    assert response.status_code == 200
    return response.json()


def pdf_text(content: bytes) -> str:
    reader = PdfReader(BytesIO(content))
    assert reader.pages
    return "\n".join(page.extract_text() or "" for page in reader.pages)


@pytest.mark.parametrize(
    ("directory", "filename", "vendor"),
    [
        ("cisco", "compliant.conf", "cisco_iosxe"),
        ("fortigate", "compliant.conf", "fortigate_fortios"),
        ("paloalto", "compliant.conf", "paloalto_panos"),
    ],
)
def test_pdf_generation_for_supported_vendors_contains_stored_results_and_evidence(
    client: TestClient,
    directory: str,
    filename: str,
    vendor: str,
) -> None:
    analysis = upload(client, directory, filename)
    response = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    text = pdf_text(response.content)
    assert text.startswith("PS 26155")
    assert "Executive Summary" in text
    assert "Control Results" in text
    assert "Evidence Details" in text
    assert vendor in text
    assert analysis["analysis_id"] in text
    assert "CTRL-001" in text
    assert "PASS" in text
    assert "CONFIGURATION" in text


def test_unknown_result_and_missing_source_are_rendered_without_fabrication(client: TestClient) -> None:
    analysis = upload(client, "cisco", "unknown.conf")
    response = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert response.status_code == 200
    text = pdf_text(response.content)
    assert "UNKNOWN" in text
    assert "Not available" in text
    assert "not available" in text.lower()


def test_adaptive_mapping_and_lineage_are_rendered(client: TestClient) -> None:
    original = upload(client, "astranet", "unknown-pattern.conf")
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    suggestion = client.post(f"/api/mappings/{pattern_id}/suggest").json()
    approved = client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "report-reviewer", "semantic_mapping": suggestion["semantic_mapping"]},
    )
    assert approved.status_code == 200
    child = client.post(f"/api/analyze/{original['analysis_id']}/reanalyze")
    assert child.status_code == 200
    child_payload = child.json()

    response = client.get(f"/api/reports/{child_payload['analysis_id']}/pdf")
    assert response.status_code == 200
    text = pdf_text(response.content)
    assert "Adaptive Mapping" in text
    assert "guard-channel lattice-secure" in text
    assert "RECOGNIZED_VIA_APPROVED_MAPPING" in text
    assert "Mapping Version" in text
    assert "Human approved" in text
    assert "The mapping was used to enrich the Security IR" in text
    assert "Parent Analysis" in text
    assert "Re-analysis" in text


def test_simulation_data_and_disclaimer_are_rendered(client: TestClient) -> None:
    analysis = upload(client, "cisco", "noncompliant.conf")
    remediation = client.get(f"/api/remediation/{analysis['analysis_id']}").json()["remediations"][0]
    simulated = client.post(
        f"/api/remediation/{analysis['analysis_id']}/simulate",
        json={"remediation_id": remediation["remediation_id"]},
    )
    assert simulated.status_code == 200

    before = get_analysis_bundle(analysis["analysis_id"])
    response = client.get(f"/api/reports/{analysis['analysis_id']}/pdf")
    assert response.status_code == 200
    text = pdf_text(response.content)
    assert "Remediation Simulation" in text
    assert "Before Result" in text
    assert "FAIL" in text
    assert "After Result" in text
    assert "Simulation Only" in text
    assert "SIMULATION ONLY" in text
    assert "No production device was contacted or modified" in text
    assert "SIMULATED_REMEDIATION" in text
    assert get_analysis_bundle(analysis["analysis_id"]) == before


def test_missing_analysis_returns_structured_report_error(client: TestClient) -> None:
    response = client.get("/api/reports/not-found/pdf")
    assert response.status_code == 404
    assert response.json() == {
        "detail": "The analysis was not found.",
        "error_code": "ANALYSIS_NOT_FOUND",
    }


def test_original_and_reanalysis_reports_are_distinct(client: TestClient) -> None:
    original = upload(client, "astranet", "unknown-pattern.conf")
    pattern_id = original["unknown_patterns"][0]["pattern_id"]
    suggestion = client.post(f"/api/mappings/{pattern_id}/suggest").json()
    client.post(
        f"/api/mappings/{pattern_id}/approve",
        json={"reviewer_id": "report-reviewer", "semantic_mapping": suggestion["semantic_mapping"]},
    )
    child = client.post(f"/api/analyze/{original['analysis_id']}/reanalyze").json()
    original_pdf = client.get(f"/api/reports/{original['analysis_id']}/pdf").content
    child_pdf = client.get(f"/api/reports/{child['analysis_id']}/pdf").content
    assert original_pdf != child_pdf
    assert original["analysis_id"] in pdf_text(original_pdf)
    assert child["analysis_id"] in pdf_text(child_pdf)
    assert "Re-analysis" in pdf_text(original_pdf)
    assert "NO" in pdf_text(original_pdf)
    assert "Adaptive Mapping" in pdf_text(child_pdf)
