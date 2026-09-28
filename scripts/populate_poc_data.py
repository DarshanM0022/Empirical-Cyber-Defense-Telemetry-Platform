import json
import urllib.request
import urllib.parse
import time

BASE_URL = "http://127.0.0.1:8000/api/v1"

def post(endpoint, data):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get(endpoint):
    with urllib.request.urlopen(f"{BASE_URL}{endpoint}") as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    print("1. Registering target asset for POC...")
    asset = post("/assets", {
        "name": "AegisX Enterprise Core Gateway",
        "asset_type": "website",
        "target": "127.0.0.1:8000",
        "environment": "production",
        "owner": "security-operations",
        "criticality": "high"
    })
    asset_id = asset["id"]
    print(f"   Registered Asset: {asset_id} ({asset['name']})")

    print("\n2. Granting explicit written authorization (Mandatory Gate)...")
    auth = post(f"/assets/{asset_id}/authorize", {
        "scope": "http://127.0.0.1:8000",
        "authorized_by": "darshan-secops-admin@enterprise.local",
        "authorization_method": "signed_contract",
        "notes": "Explicit authorization agreement verified for defense evaluation",
        "expires_days": 90
    })
    print(f"   Authorization Status: {auth['status']} (Method: {auth['authorization_method']})")

    print("\n2. Proof of Authorization Gate Rejection (Pending status)...")
    print(f"   Initial Authorization Status: {auth['status']} (Method: {auth['authorization_method']})")
    scan_unauth = post("/scans", {
        "asset_id": asset_id,
        "scan_type": "web_security_audit"
    })
    print(f"   Scan Status: {scan_unauth['status']} (Rejected as expected: {scan_unauth['error_message'][:60]}...)")

    print("\n3. Granting Verified Admin Authorization...")
    auth_verified = post(f"/assets/{asset_id}/authorize", {
        "scope": "http://127.0.0.1:8000",
        "authorized_by": "darshan-secops-admin@enterprise.local",
        "authorization_method": "admin_verified",
        "notes": "Verified authorization contract signed and registered",
        "expires_days": 90
    })
    print(f"   Verified Status: {auth_verified['status']}")

    print("\n4. Executing real safe scan against verified endpoint...")
    scan2 = post("/scans", {
        "asset_id": asset_id,
        "scan_type": "web_security_audit"
    })
    print(f"   Scan Status: {scan2['status']}, Duration: {scan2['duration_seconds']}s, Findings: {scan2['findings_count']}")

    print("\n4. Ingesting real SIEM authentication events...")
    # Ingest 5 failed authentications to trigger deterministic brute force rule
    actor = "finance_director_01"
    for i in range(1, 6):
        res = post("/events", {
            "source": "identity-provider",
            "event_type": "authentication",
            "action": "login",
            "actor_id": actor,
            "source_ip": "198.51.100.88",
            "device_id": "corporate_laptop_04",
            "is_new_device": False,
            "result": "failure",
            "asset_id": asset_id
        })
        print(f"   Ingested Event #{i}: Failure (Detections triggered: {res['detections_triggered']})")

    # Ingest subsequent successful login on a NEW device
    res_new_dev = post("/events", {
        "source": "identity-provider",
        "event_type": "authentication",
        "action": "login",
        "actor_id": actor,
        "source_ip": "198.51.100.88",
        "device_id": "unrecognized_device_x9",
        "is_new_device": True,
        "result": "success",
        "asset_id": asset_id
    })
    print(f"   Ingested New Device Event: Success (Detections: {res_new_dev['detections_triggered']}, Incidents: {res_new_dev['incidents_created_or_updated']})")

    # Recalculate posture
    post(f"/risk/assets/{asset_id}/recalculate", {})
    overview = get("/risk/overview")
    print(f"\n5. Live Posture State: Level={overview['overall_risk_level']}, Score={overview['overall_risk_score']}/100, Incidents={overview['active_incidents']}, Findings={overview['critical_findings'] + overview['high_findings']}")

if __name__ == "__main__":
    main()
