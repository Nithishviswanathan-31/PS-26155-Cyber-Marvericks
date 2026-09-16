from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.storage.database import reset_demo_database

ROOT=Path(__file__).resolve().parents[2]
@pytest.fixture
def client():
    reset_demo_database()
    with TestClient(app) as value: yield value
    reset_demo_database()
def upload(client,name="compliant.conf"):
    return client.post("/api/analyze",files={"file":(name,(ROOT/"configs/cisco"/name).read_bytes(),"text/plain")}).json()
def test_console_summary_history_search_and_pagination(client):
    one=upload(client); two=upload(client,"noncompliant.conf"); three=upload(client)
    summary=client.get("/api/dashboard/summary").json()
    assert summary["total_devices"] == 2 and summary["total_analyses"] == 3
    assert summary["pass_findings"] and summary["fail_findings"]
    page=client.get("/api/analyses?limit=1").json(); second=client.get("/api/analyses?limit=1&offset=1").json(); assert page["total"]==3 and len(page["items"])==1 and page["items"][0]["analysis_id"] != second["items"][0]["analysis_id"]
    assert client.get(f"/api/analyses?q={one['analysis_id']}").json()["total"]==1
    assert client.get(f"/api/devices?q={one['device']['device_id']}").json()["total"]==1
    assert client.get(f"/api/configurations?q={two['configuration']['configuration_id']}").json()["total"]==1
def test_console_findings_and_batch_history_are_persisted(client):
    content=(ROOT/"configs/cisco/compliant.conf").read_bytes()
    batch=client.post("/api/batches/analyze",files=[("files",("a.conf",content,"text/plain")),("files",("b.conf",content,"text/plain"))]).json()
    history=client.get("/api/batches").json(); assert history["total"]==1 and history["items"][0]["batch_id"]==batch["batch_id"]
    findings=client.get("/api/findings?status=PASS").json(); assert findings and all(item["result"]["result"]=="PASS" for item in findings)
    assert client.get("/api/knowledge/review-queue").status_code==200
