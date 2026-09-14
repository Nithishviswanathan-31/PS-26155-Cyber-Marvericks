from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.storage.database import get_analysis_result


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = PROJECT_ROOT / "configs" / "cisco"
FORTIGATE_CONFIG_ROOT = PROJECT_ROOT / "configs" / "fortigate"
PALOALTO_CONFIG_ROOT = PROJECT_ROOT / "configs" / "paloalto"
ASTRANET_CONFIG_ROOT = PROJECT_ROOT / "configs" / "astranet"


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def upload(client: TestClient, filename: str) -> object:
    content = (CONFIG_ROOT / filename).read_bytes()
    return client.post(
        "/api/analyze",
        files={"file": (filename, content, "text/plain")},
    )


def upload_fortigate(client: TestClient, filename: str) -> object:
    content = (FORTIGATE_CONFIG_ROOT / filename).read_bytes()
    return client.post(
        "/api/analyze",
        files={"file": (filename, content, "text/plain")},
    )


def upload_paloalto(client: TestClient, filename: str) -> object:
    content = (PALOALTO_CONFIG_ROOT / filename).read_bytes()
    return client.post(
        "/api/analyze",
        files={"file": (filename, content, "text/plain")},
    )


def upload_astranet(client: TestClient, filename: str) -> object:
    content = (ASTRANET_CONFIG_ROOT / filename).read_bytes()
    return client.post(
        "/api/analyze",
        files={"file": (filename, content, "text/plain")},
    )


def test_api_accepts_valid_cisco_configuration(client: TestClient) -> None:
    response = upload(client, "compliant.conf")
    assert response.status_code == 200


def test_compliant_fixture_returns_expected_pass_results(client: TestClient) -> None:
    response = upload(client, "compliant.conf")
    payload = response.json()
    assert {item["result"] for item in payload["results"]} == {"PASS"}


def test_noncompliant_fixture_returns_expected_fail_results(client: TestClient) -> None:
    response = upload(client, "noncompliant.conf")
    payload = response.json()
    assert {item["result"] for item in payload["results"]} == {"FAIL"}


def test_unknown_fixture_returns_unknown_results(client: TestClient) -> None:
    response = upload(client, "unknown.conf")
    payload = response.json()
    assert {item["result"] for item in payload["results"]} == {"UNKNOWN"}
    assert payload["unknown_patterns"]


def test_response_contains_unique_analysis_id(client: TestClient) -> None:
    first = upload(client, "compliant.conf").json()
    second = upload(client, "compliant.conf").json()
    assert first["analysis_id"]
    assert second["analysis_id"]
    assert first["analysis_id"] != second["analysis_id"]


def test_response_contains_vendor(client: TestClient) -> None:
    payload = upload(client, "compliant.conf").json()
    assert payload["vendor"] == "cisco_iosxe"


def test_api_routes_fortigate_configuration_to_fortigate_parser(client: TestClient) -> None:
    response = upload_fortigate(client, "compliant.conf")
    assert response.status_code == 200
    payload = response.json()
    assert payload["vendor"] == "fortigate_fortios"
    assert {item["result"] for item in payload["results"]} == {"PASS"}


def test_api_routes_paloalto_configuration_to_paloalto_parser(client: TestClient) -> None:
    response = upload_paloalto(client, "compliant.conf")
    assert response.status_code == 200
    payload = response.json()
    assert payload["vendor"] == "paloalto_panos"
    assert payload["device"]["hostname"] == "demo-paloalto-compliant"
    assert {item["result"] for item in payload["results"]} == {"PASS"}


def test_api_routes_synthetic_astranet_to_astranet_parser(client: TestClient) -> None:
    response = upload_astranet(client, "unknown-pattern.conf")
    assert response.status_code == 200
    payload = response.json()
    assert payload["vendor"] == "astranet"
    assert payload["device"]["hostname"] == "demo-astranet-unknown"
    assert {item["result"] for item in payload["results"]} == {"UNKNOWN"}
    assert len(payload["unknown_patterns"]) == 1
    assert payload["unknown_patterns"][0]["raw_pattern"] == "guard-channel lattice-secure"
    assert payload["unknown_patterns"][0]["source_file"] == "unknown-pattern.conf"
    assert payload["unknown_patterns"][0]["line_start"] == 5


def test_response_contains_device_metadata(client: TestClient) -> None:
    device = upload(client, "compliant.conf").json()["device"]
    assert device["hostname"] == "demo-cisco-compliant"
    assert device["version"] == "17.9"


def test_response_contains_control_results(client: TestClient) -> None:
    results = upload(client, "compliant.conf").json()["results"]
    assert [item["control_id"] for item in results] == [
        "CTRL-001",
        "CTRL-002",
        "CTRL-003",
        "CTRL-004",
    ]


def test_response_contains_evidence(client: TestClient) -> None:
    evidence = upload(client, "noncompliant.conf").json()["evidence"]
    assert evidence
    assert {item["control_id"] for item in evidence} == {
        "CTRL-001",
        "CTRL-002",
        "CTRL-003",
        "CTRL-004",
    }


def test_evidence_contains_source_filename(client: TestClient) -> None:
    evidence = upload(client, "noncompliant.conf").json()["evidence"]
    assert all(item["source_file"] == "noncompliant.conf" for item in evidence)


def test_evidence_contains_correct_line_numbers(client: TestClient) -> None:
    evidence = upload(client, "noncompliant.conf").json()["evidence"]
    logging_evidence = next(item for item in evidence if item["property"] == "logging.enabled")
    assert logging_evidence["line_start"] == 5
    assert logging_evidence["line_end"] == 5


def test_evidence_contains_raw_excerpts(client: TestClient) -> None:
    evidence = upload(client, "noncompliant.conf").json()["evidence"]
    logging_evidence = next(item for item in evidence if item["property"] == "logging.enabled")
    assert logging_evidence["raw_excerpt"] == "no logging buffered 16384"


def test_empty_file_is_rejected_safely(client: TestClient) -> None:
    response = client.post(
        "/api/analyze",
        files={"file": ("empty.conf", b"", "text/plain")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_unsupported_input_is_rejected_safely(client: TestClient) -> None:
    response = client.post(
        "/api/analyze",
        files={"file": ("unknown.conf", b"<panos><config /></panos>", "text/plain")},
    )
    assert response.status_code == 400
    assert "Cisco" in response.json()["detail"]
    assert "FortiGate" in response.json()["detail"]
    assert "AstraNet" in response.json()["detail"]


def test_malformed_non_utf8_input_is_rejected_safely(client: TestClient) -> None:
    response = client.post(
        "/api/analyze",
        files={"file": ("malformed.conf", b"\xff\xfe\x00", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "UTF-8" in response.json()["detail"]


def test_invalid_file_type_is_rejected_safely(client: TestClient) -> None:
    response = client.post(
        "/api/analyze",
        files={"file": ("config.xml", b"version 17.9", "text/xml")},
    )
    assert response.status_code == 400
    assert "file type" in response.json()["detail"].lower()


def test_analysis_result_is_persisted_without_original_file_content(client: TestClient) -> None:
    response = upload(client, "compliant.conf")
    analysis_id = response.json()["analysis_id"]
    saved = get_analysis_result(analysis_id)
    assert saved is not None
    assert saved["analysis_id"] == analysis_id
    assert "configuration_text" not in saved


def test_openapi_exposes_multipart_analysis_endpoint(client: TestClient) -> None:
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    operation = openapi.json()["paths"]["/api/analyze"]["post"]
    content = operation["requestBody"]["content"]
    assert "multipart/form-data" in content


def test_http_upload_to_evidence_vertical_slice(client: TestClient) -> None:
    payload = upload(client, "noncompliant.conf").json()
    logging_evidence = next(item for item in payload["evidence"] if item["property"] == "logging.enabled")
    assert payload["vendor"] == "cisco_iosxe"
    assert payload["results"][1]["result"] == "FAIL"
    assert logging_evidence["control_id"] == "CTRL-002"
    assert logging_evidence["result"] == "FAIL"
    assert logging_evidence["expected"] is True
    assert logging_evidence["actual"] is False
    assert logging_evidence["source_file"] == "noncompliant.conf"
    assert logging_evidence["line_start"] == 5
    assert logging_evidence["raw_excerpt"] == "no logging buffered 16384"
