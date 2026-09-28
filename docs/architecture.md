# AegisX System Architecture

## Design Philosophy: No Invented Security Events
AegisX operates strictly on empirical evidence. Rather than creating generic "threat alert" flags with arbitrary confidence scores, AegisX enforces:
1. **Provenance Chains**: Every finding links back to an exact cryptographic evidence artifact (raw socket payload, HTTP response headers, status codes, timestamps, and tool versions).
2. **Mandatory Authorization Gate**: Scanning engine will actively abort execution if the target asset lacks an active, cryptographic or administrator-verified authorization contract.
3. **Transparent Risk Breakdown**: Risk scores are calculated with documented $+X$ and $-Y$ rationales directly traceable to verifiable factors.

## Architectural Components

```
                          ┌────────────────────────┐
                          │  AegisX Web Dashboard  │
                          │   & REST API Clients   │
                          └───────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │    API Gateway/Router   │
                         │    (/api/v1 endpoints)  │
                         └────────────┬────────────┘
                                      │
       ┌──────────────────────────────┼──────────────────────────────┐
       │                              │                              │
┌──────▼──────┐               ┌───────▼───────┐              ┌───────▼───────┐
│ Asset & Auth│               │  Real Scanner │              │ SIEM Event    │
│ Service     │               │  Engine       │              │ Ingestion     │
└──────┬──────┘               └───────┬───────┘              └───────┬───────┘
       │                              │                              │
       │    ┌─────────────────────────┴─────────┐                    │
       │    │ Safe Web Scanner (TLS & HTTP)     │                    │
       │    │ Evidence Recorder (Hash & Proven.)│                    │
       │    └─────────────────────────┬─────────┘                    │
       │                              │                              │
       └──────────────────────────────┼──────────────────────────────┘
                                      │
                            ┌─────────▼─────────┐
                            │ Detection Engine  │
                            │ (Deterministic)   │
                            └─────────┬─────────┘
                                      │
                            ┌─────────▼─────────┐
                            │ Correlation &     │
                            │ Incident Engine   │
                            └─────────┬─────────┘
                                      │
                            ┌─────────▼─────────┐
                            │ Transparent Risk  │
                            │ Calculation Engine│
                            └───────────────────┘
```

## Data Model
- **Asset**: Target system (domain, endpoint, VM, server) with environment tags and ownership.
- **Authorization**: Proof of explicit permission with scope, challenge token, verification timestamp, and expiration.
- **Scan**: Scheduled or ad-hoc scan run tied to authorized targets.
- **Finding & Evidence**: Empirical vulnerabilities with confidence (`observed`, `suspected`, `confirmed`), full raw HTTP headers, TLS certificate details, and SHA-256 evidence digests.
- **SIEM Event & Detection**: Standardized security event format (actor, device, network, action, result) with deterministic rule evaluation.
- **Incident**: Grouped correlation of findings, detections, and timeline for an asset.
- **RiskScore & AuditLog**: Full explanation tree and immutable audit trail.
