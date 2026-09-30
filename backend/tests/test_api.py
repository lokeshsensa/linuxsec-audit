import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data

def test_api_system():
    response = client.get("/api/system")
    assert response.status_code == 200
    data = response.json()
    assert "hostname" in data
    assert "os_name" in data

def test_api_services():
    response = client.get("/api/services")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_api_network_ports():
    response = client.get("/api/network/ports")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_api_start_audit_and_retrieve():
    # Trigger audit in demo mode
    start_resp = client.post("/api/audit/start", json={"demo_mode": True})
    assert start_resp.status_code == 200
    audit_data = start_resp.json()
    audit_id = audit_data["id"]
    assert audit_id.startswith("aud-")
    assert audit_data["risk_score"] >= 0
    assert len(audit_data["findings"]) > 0

    # Retrieve audit
    get_resp = client.get(f"/api/audit/{audit_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == audit_id

    # Retrieve findings with filter
    f_resp = client.get(f"/api/audit/{audit_id}/findings?severity=HIGH")
    assert f_resp.status_code == 200
    high_findings = f_resp.json()
    for f in high_findings:
        assert f["severity"] == "HIGH"

    # Export reports
    json_resp = client.get(f"/api/reports/{audit_id}/json")
    assert json_resp.status_code == 200

    csv_resp = client.get(f"/api/reports/{audit_id}/csv")
    assert csv_resp.status_code == 200
    assert "Finding ID" in csv_resp.text

    html_resp = client.get(f"/api/reports/{audit_id}/html")
    assert html_resp.status_code == 200
    assert "LinuxSecAudit" in html_resp.text
