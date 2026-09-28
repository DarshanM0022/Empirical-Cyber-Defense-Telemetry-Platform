# AegisX — Evidence-Producing Defensive Cybersecurity Platform

AegisX is an enterprise-grade, evidence-producing cybersecurity platform designed with a fundamental rule: **No invented security events.**

Every security finding, detection, and risk evaluation has verifiable cryptographic provenance, real network/telemetry evidence, and transparent scoring breakdowns.

## Core Features (v0.1)

1. **Strict Asset Authorization Gate**: Scans are strictly prohibited unless the asset has a verified, non-expired authorization record.
2. **Safe, Real-World Scanner**:
   - TLS/SSL Inspection: Real socket handshakes, certificate chain verification, expiration detection, SAN matching, cipher suites.
   - HTTP Security Inspection: Verifies HTTPS redirection, analyzes HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Cookie flags (`Secure`, `HttpOnly`, `SameSite`), and server software disclosure.
   - Raw Evidence Provenance: Captures exact requests, response headers, status codes, timestamps, and SHA-256 evidence hashes.
3. **SIEM Event Normalization & Detection Engine**:
   - Standardized event ingestion model (actor, device, network, action, result).
   - Real, deterministic threat detections (e.g., credential brute force, suspicious authentication patterns, new device access).
4. **Transparent Risk Engine**:
   - No black-box magic numbers.
   - Auditable risk calculation with discrete point additions and subtractions based on verified findings and exposure.
5. **Incident Correlation & Audit Logging**:
   - Correlates findings and security detections per asset into auditable incidents.
   - Immutable audit logging for all user and system operations.
6. **Interactive Web Console & REST API**:
   - Full REST API with OpenAPI documentation at `/docs`.
   - Real-time web dashboard for asset management, live scanning, finding inspection, SIEM telemetry, and incident response.
