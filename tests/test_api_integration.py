from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_api_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "AegisX" in data["service"]

def test_asset_lifecycle_and_authorization():
    # 1. Register asset
    asset_payload = {
        "name": "Integration Test Portal",
        "asset_type": "website",
        "target": "portal.test.internal",
        "environment": "staging",
        "owner": "security-team",
        "criticality": "medium"
    }
    create_res = client.post("/api/v1/assets", json=asset_payload)
    assert create_res.status_code == 201
    asset_data = create_res.json()
    asset_id = asset_data["id"]
    assert asset_data["name"] == "Integration Test Portal"

    # 2. Check authorization gate before authorizing
    scan_res = client.post("/api/v1/scans", json={"asset_id": asset_id, "scan_type": "web_security_audit"})
    assert scan_res.status_code == 201
    scan_data = scan_res.json()
    assert scan_data["status"] == "rejected_unauthorized"

    # 3. Grant verified authorization
    auth_payload = {
        "scope": "https://portal.test.internal",
        "authorized_by": "lead-auditor",
        "authorization_method": "admin_verified",
        "notes": "Verified for defense evaluation",
        "expires_days": 60
    }
    auth_res = client.post(f"/api/v1/assets/{asset_id}/authorize", json=auth_payload)
    assert auth_res.status_code == 200
    auth_data = auth_res.json()
    assert auth_data["status"] == "verified"
    assert auth_data["challenge_token"].startswith("aegisx-challenge-")

    # 4. Ingest SIEM Event
    event_payload = {
        "source": "identity-provider",
        "event_type": "authentication",
        "action": "login",
        "actor_id": "auditor_1",
        "result": "failure",
        "source_ip": "198.51.100.99",
        "asset_id": asset_id
    }
    event_res = client.post("/api/v1/events", json=event_payload)
    assert event_res.status_code == 201
    assert event_res.json()["status"] == "ingested"

    # 5. Query Real Telemetry Stats
    stats_res = client.get("/api/v1/events/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "telemetry_counts" in stats

    # 6. Query Risk Overview & Asset Breakdown
    risk_res = client.get(f"/api/v1/risk/assets/{asset_id}")
    assert risk_res.status_code == 200
    risk_data = risk_res.json()
    assert "score" in risk_data
    assert "factors" in risk_data

    overview_res = client.get("/api/v1/risk/overview")
    assert overview_res.status_code == 200
    overview = overview_res.json()
    assert "overall_risk_level" in overview

    # 7. Audit Report in JSON and HTML
    json_rep = client.get(f"/api/v1/reports/assets/{asset_id}/json")
    assert json_rep.status_code == 200
    assert json_rep.json()["report_metadata"]["evidence_integrity_policy"] == "NO_INVENTED_SECURITY_EVENTS"

    html_rep = client.get(f"/api/v1/reports/assets/{asset_id}/html")
    assert html_rep.status_code == 200
    assert "text/html" in html_rep.headers["content-type"]
    assert "AegisX Defensive Security Assessment" in html_rep.text

    # 8. Query Audit Trail
    audit_res = client.get("/api/v1/audit")
    assert audit_res.status_code == 200
    logs = audit_res.json()
    assert len(logs) > 0
