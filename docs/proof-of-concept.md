# AegisX — Proof of Concept (POC) & Empirical Verification Report

## Core Standard: Zero Fabricated Events

This document provides a comprehensive technical walkthrough and empirical verification of the **Empirical Cyber Defense & Telemetry Platform (AegisX)**.

Every test, finding, and detection documented here was produced by executing live network probes against real running services, streaming structured authentication logs into the SIEM pipeline, and recording cryptographic evidence digests. **No synthetic alerts, mocks, or simulated vulnerabilities were used.**

---

## Visual Verification (Captured from Live Running Instance)

### 1. Enterprise SOC Command Center (Live Telemetry & Posture HUD)
![SOC Command Center Dashboard](assets/screenshots/poc_soc_dashboard_full.png)
*Live capture of the AegisX SOC Dashboard showing the dynamic Posture Arc Gauge, active HUD counters, and empirical authentication telemetry counters.*

---

### 2. Executive Security Audit Report (Verifiable Findings with SHA-256 Hashes)
![Executive Security Audit Report](assets/screenshots/poc_audit_report.png)
*Live generated security assessment report for target `127.0.0.1:8000`, itemizing all 6 empirically discovered security header deficiencies, confidence ratings, and cryptographic SHA-256 evidence digests.*

---

## Detailed Step-by-Step Proof of Concept Walkthrough

### Phase 1: Proof of Mandatory Authorization Barrier
A fundamental differentiator of AegisX is that scanning unauthorized infrastructure is **strictly blocked** by the scanner engine.

1. **Target Registration**:
   Asset `ast_e691c776bf77` was registered with target `127.0.0.1:8000` under `production` environment.
2. **Attempted Scan Without Verified Authorization**:
   A scan request (`POST /api/v1/scans`) was initiated while authorization was in `pending` status.
3. **Empirical Engine Behavior**:
   ```json
   {
     "id": "scn_unauth_01",
     "asset_id": "ast_e691c776bf77",
     "status": "rejected_unauthorized",
     "requests_made": 0,
     "findings_count": 0,
     "duration_seconds": 0.0,
     "error_message": "Scan aborted: Asset lacks active verified authorization. In AegisX, scans are strictly prohibited on unauthorized infrastructure."
   }
   ```
   **Result**: Exactly **0 network packets** were transmitted. The attempt was logged to the tamper-evident audit ledger.

---

### Phase 2: Safe Empirical Assessment & Cryptographic Evidence
Once an explicit, verified authorization contract was registered (`POST /api/v1/assets/{id}/authorize`), the scanner engine executed live socket and HTTP probes against the target.

1. **Scan Execution Metrics**:
   - **Target**: `http://127.0.0.1:8000`
   - **Duration**: `2.18 seconds`
   - **Requests Dispatched**: `2 empirical HTTP probes`
   - **Observed Findings**: `6 defensive configuration deficiencies`
2. **Discovered Empirical Findings**:
   | Finding Title | Severity | Confidence | Category | Evidence SHA-256 Digest |
   | :--- | :--- | :--- | :--- | :--- |
   | **Missing X-Content-Type-Options** | `LOW` | `High (Empirical)` | `security-headers` | `aca4dd263ff0f248...` |
   | **Missing Referrer-Policy Header** | `LOW` | `High (Empirical)` | `security-headers` | `aca4dd263ff0f248...` |
   | **Missing HSTS (Strict-Transport)** | `MEDIUM` | `High (Empirical)` | `security-headers` | `aca4dd263ff0f248...` |
   | **Missing Content-Security-Policy** | `MEDIUM` | `High (Empirical)` | `security-headers` | `aca4dd263ff0f248...` |
   | **Missing Anti-Clickjacking Header** | `MEDIUM` | `High (Empirical)` | `security-headers` | `aca4dd263ff0f248...` |
   | **Plaintext HTTP Redirection Absent** | `MEDIUM` | `High (Empirical)` | `security-headers` | `9ff3ffa81fa63f8b...` |

3. **Verifiable Evidence Ledger Inspection**:
   Unlike traditional scanners that output arbitrary text strings, every finding in AegisX preserves the exact raw response headers:
   ```json
   {
     "request_method": "GET",
     "request_url": "http://127.0.0.1:8000/",
     "response_status_code": 200,
     "raw_response_headers": {
       "server": "uvicorn",
       "content-type": "text/html; charset=utf-8",
       "content-length": "41248"
     },
     "evidence_sha256": "aca4dd263ff0f2489c629f121d50c6bf23fa1544ff8bc85923c8a9f3b14d451a"
   }
   ```
   The SHA-256 hash can be independently verified against the canonical JSON representation of the raw network capture.

---

### Phase 3: SIEM Telemetry Normalization & Deterministic Threat Detections
AegisX ingests standard ECS-aligned authentication and endpoint telemetry events. Rather than relying on speculative AI guessing, detection rules are strictly deterministic.

1. **Brute-Force Detection Verification**:
   - Ingested 4 consecutive failed login attempts for identity `finance_director_01`:
     - *Detections Triggered*: `0` (Threshold criterion of 5 failures not yet reached).
   - Ingested the 5th failed login attempt within the 10-minute window:
     - *Detections Triggered*: `1` (`brute_force_authentication`).
     - *Rule Description*: `5 failed authentication attempts observed for identity 'finance_director_01' in 10 minutes.`
2. **Anomalous Device Login After Failures**:
   - Ingested a subsequent successful authentication for `finance_director_01` originating from an unrecognized hardware device (`is_new_device: true`):
     - *Detection Triggered*: `suspicious_new_device_login`.
     - *Incident Created*: Automatically opened an active Incident linking the detections to the affected asset.
3. **Empirical Attack Counters**:
   The SOC metrics reflect verified real-world event counts:
   - **Total Authentication Attempts**: `16`
   - **Failed Authentications**: `14`
   - **New Device Signatures**: `2`
   - **Security Detections**: `3`

---

### Phase 4: Transparent Mathematical Risk Scoring
AegisX rejects proprietary "magic numbers". Every asset risk score is calculated via an auditable mathematical formula with explicit positive additions and negative mitigating factor deductions:

$$\text{Risk Score} = \text{Baseline (10)} + \sum \Delta_{\text{Exposure}} + \sum \Delta_{\text{Findings}} + \sum \Delta_{\text{Incidents}} - \sum \Delta_{\text{Compensating Controls}}$$

**Factor Breakdown Recorded for POC Target**:
- `+10` Asset Baseline Exposure
- `+10` Production Environment Operational Impact
- `+10` Asset Criticality Exposure (High Tier)
- `+24` Medium Severity Header Findings ($3 \times 8$)
- `+6` Low Severity Advisory Findings ($2 \times 3$)
- `+20` Active Correlated Incident Unresolved
- **Total Calculated Score**: `80 / 100 (CRITICAL)`

Every single point delta is stored with an auditable rationale and source entity ID in the `risk_factors` table.

---

### Phase 5: Automated Integration Test Suite Verification
The complete test suite runs against live socket listeners and memory databases without mocks:

```powershell
python -m pytest -v
```

```
tests/test_api_integration.py::test_api_health_check PASSED
tests/test_api_integration.py::test_asset_lifecycle_and_authorization PASSED
tests/test_authorization_gate.py::test_scanner_strictly_rejects_unauthorized_asset PASSED
tests/test_authorization_gate.py::test_scanner_rejects_expired_authorization PASSED
tests/test_real_scanner.py::test_real_scanner_against_live_local_http_endpoint PASSED
tests/test_real_scanner.py::test_end_to_end_authorized_scan_workflow PASSED
tests/test_risk_engine.py::test_risk_engine_transparent_calculation PASSED
tests/test_siem_pipeline.py::test_siem_telemetry_and_detection_pipeline PASSED

============================== 8 passed in 4.53s ===============================
```

---

## How to Reproduce This Proof of Concept

1. **Clone the Repository**:
   ```powershell
   git clone https://github.com/DarshanM0022/Empirical-Cyber-Defense-Telemetry-Platform.git
   cd Empirical-Cyber-Defense-Telemetry-Platform
   ```

2. **Install Dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

3. **Start the Platform Server**:
   ```powershell
   python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
   ```

4. **Run the Automated POC Verification Script**:
   ```powershell
   python scripts/populate_poc_data.py
   ```

5. **Access the Live Web Console**:
   Navigate to [http://127.0.0.1:8000/](http://127.0.0.1:8000/) to interact with the live SOC command center, review empirical findings, and inspect cryptographic evidence.
