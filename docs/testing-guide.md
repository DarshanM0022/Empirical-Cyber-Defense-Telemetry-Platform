# AegisX Testing Guide: Real-World Testing With No Simulation

## Core Testing Philosophy
In accordance with the prompt's instructions:
1. **No Simulated Scans**: We test the scanner against real HTTP and TLS endpoints. For localized automated testing, we launch a real TCP/HTTP server process to receive and respond to real sockets and HTTP requests.
2. **Strict Authorization**: We verify that targeting any unauthorized hostname triggers an immediate security abort.
3. **Evidence Integrity**: We verify that the evidence records produced contain the actual raw HTTP headers and TLS handshakes, plus cryptographic digests.
4. **Deterministic SIEM & Detection**: We feed real structured authentication telemetry events into the ingestion pipeline and test threshold detections.
5. **Real-World Testing on Controlled Assets**: Instructions are provided below for scanning your actual personal domain or local web application.

---

## 1. Automated Test Suite Execution
To run the automated test suite:
```powershell
pytest -v tests/
```

This executes:
- `test_authorization_gate.py`: Verifies that unauthorized targets are rejected before making network requests.
- `test_real_scanner.py`: Spins up a real HTTP/HTTPS test server on a local port, scans it with AegisX, and verifies that real headers and missing security headers are recorded as evidence with exact raw text.
- `test_siem_pipeline.py`: Ingests real authentication event logs and verifies that brute-force / threshold rules generate deterministic detections.
- `test_risk_engine.py`: Verifies that positive and negative risk factors calculate mathematically correct and auditable scores.
- `test_api_integration.py`: Tests the entire REST API workflow from asset creation to authorization, scan triggering, finding review, and report export.

---

## 2. Real-World Scanning of Your Own Asset
To scan your own live asset (e.g., your personal website or a test API server):

### Step 1: Start AegisX Backend & Dashboard
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at `http://127.0.0.1:8000`.

### Step 2: Register Your Asset
Send a POST request or use the Web Console:
```json
POST /api/v1/assets
{
  "name": "My Personal Web Application",
  "asset_type": "website",
  "target": "example.com",
  "environment": "production",
  "owner": "security-team",
  "criticality": "high"
}
```

### Step 3: Authorize the Asset
AegisX requires authorization before any scan is permitted:
```json
POST /api/v1/assets/{asset_id}/authorize
{
  "scope": "https://example.com",
  "authorized_by": "darsh-security-admin",
  "authorization_method": "admin_verified",
  "notes": "Explicit authorization granted for defensive assessment",
  "expires_days": 90
}
```

### Step 4: Run Safe Scan
```json
POST /api/v1/scans
{
  "asset_id": "{asset_id}",
  "scan_type": "web_security_audit"
}
```
AegisX connects directly to the target, performs safe TLS and HTTP inspection, hashes the evidence, and generates findings.
