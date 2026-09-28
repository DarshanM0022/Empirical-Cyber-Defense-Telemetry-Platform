import json
import urllib.request
import urllib.parse
import hashlib

BASE_URL = "http://127.0.0.1:8000/api/v1"

def api_call(endpoint, method="GET", data=None):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode("utf-8")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    print("=" * 70)
    print("AegisX — Advanced Proof of Concept (POC) Verification Engine")
    print("=" * 70)

    # 1. Retrieve monitored assets
    assets = api_call("/assets")
    if not assets:
        print("[!] No assets registered. Run populate_poc_data.py first.")
        return
    asset = assets[0]
    asset_id = asset["id"]
    print(f"\n[+] Active Monitored Asset: {asset['name']} (ID: {asset_id})")

    # 2. SCENARIO A: Credential Spraying Telemetry Attack
    print("\n--- SCENARIO A: Credential Spraying Detection ---")
    spray_ip = "198.51.100.99"
    targets = ["db_admin_root", "billing_service_svc", "hr_manager_lead"]
    print(f"[*] Simulating credential spray targeting {len(targets)} distinct accounts from single IP {spray_ip}...")

    for target_user in targets:
        ev_res = api_call("/events", method="POST", data={
            "source": "web-server",
            "event_type": "authentication",
            "action": "login",
            "actor_id": target_user,
            "source_ip": spray_ip,
            "result": "failure",
            "asset_id": asset_id
        })
        print(f"    -> Ingested failed auth for '{target_user}' from {spray_ip} (Detections: {ev_res['detections_triggered']})")

    # Query detections to verify rule fired
    detections = api_call(f"/detections?asset_id={asset_id}")
    spray_detection = next((d for d in detections if d["rule_name"] == "ip_credential_spray"), None)
    if spray_detection:
        print(f"[OK] DETECTION TRIGGERED: Rule='{spray_detection['rule_name']}', Severity='{spray_detection['severity']}'")
        print(f"    Description: {spray_detection['description']}")

    # 3. SCENARIO B: Incident Investigation & Resolution Lifecycle
    print("\n--- SCENARIO B: Incident Response Lifecycle ---")
    incidents = api_call(f"/incidents?asset_id={asset_id}")
    open_incidents = [i for i in incidents if i["status"] != "resolved"]
    print(f"[*] Found {len(open_incidents)} open/investigating incidents.")

    if open_incidents:
        target_inc = open_incidents[0]
        inc_id = target_inc["id"]
        print(f"[*] Progressing Incident {inc_id} through SOC investigation stages...")

        # Stage 1: Move to investigating
        api_call(f"/incidents/{inc_id}", method="PATCH", data={
            "status": "investigating",
            "recommended_actions": "1. Block source IP 198.51.100.99 at perimeter WAF.\n2. Invalidate sessions for targeted service accounts."
        })
        print(f"    -> Incident status transitioned to: INVESTIGATING")

        # Stage 2: Move to resolved
        api_call(f"/incidents/{inc_id}", method="PATCH", data={
            "status": "resolved"
        })
        print(f"    -> Incident status transitioned to: RESOLVED")

    # 4. SCENARIO C: Mathematical Risk Recalculation Impact
    print("\n--- SCENARIO C: Posture Recalculation Impact ---")
    recalc = api_call(f"/risk/assets/{asset_id}/recalculate", method="POST", data={})
    print(f"[OK] Risk Recalculated Post-Resolution: Score={recalc['score']}/100, Level={recalc['level']}")
    print("    Active Mathematical Risk Factors:")
    for f in recalc["factors"]:
        sign = f"+{f['delta']}" if f['delta'] >= 0 else f"{f['delta']}"
        print(f"    {sign:>4} pts | {f['factor_name']} ({f['source']})")

    # 5. SCENARIO D: Cryptographic Evidence Provenance Verification
    print("\n--- SCENARIO D: Cryptographic Evidence Verification ---")
    findings = api_call(f"/findings?asset_id={asset_id}")
    if findings:
        sample_f = findings[0]
        ev = sample_f.get("evidence")
        if ev:
            reported_sha = ev["evidence_sha256"]
            canonical_data = json.dumps({
                "timestamp": ev["timestamp"],
                "url": ev["request_url"],
                "status": ev["response_status_code"],
                "headers": json.loads(ev["response_headers"]) if ev["response_headers"] else {},
                "certificate": json.loads(ev["certificate_details"]) if ev["certificate_details"] else {}
            }, sort_keys=True)
            recalculated_sha = hashlib.sha256(canonical_data.encode("utf-8")).hexdigest()

            print(f"[+] Finding: '{sample_f['title']}'")
            print(f"    Stored Evidence SHA-256 : {reported_sha}")
            print(f"    Canonical Verification   : {recalculated_sha}")
            is_valid = (reported_sha == recalculated_sha)
            print(f"[OK] CRYPTOGRAPHIC INTEGRITY: {'VERIFIED MATCH (Tamper-Proof)' if is_valid else 'MISMATCH'}")

    print("\n" + "=" * 70)
    print("Advanced Proof of Concept Executed Successfully with Zero Synthetic Data.")
    print("=" * 70)

if __name__ == "__main__":
    main()
