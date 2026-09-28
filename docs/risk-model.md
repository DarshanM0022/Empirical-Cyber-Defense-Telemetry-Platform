# AegisX Auditable Risk Engine Model

## Core Tenet: Transparent Scoring, Zero Magic Weights
In enterprise security, an arbitrary score (e.g. "Risk: 74") is meaningless unless every point change is fully explainable, auditable, and traceable to real observations.

AegisX implements a baseline-anchored, rules-based transparent risk engine where every adjustment generates an auditable `RiskFactor` record.

## Formula & Logic Breakdown

### Baseline
- An asset starts at a baseline score of **10** (Minimal risk baseline).
- The final score is bounded in the range `[0, 100]`.

### Risk Categories:
- `0 - 24`: **LOW** (Safe, proper security headers and TLS controls in place)
- `25 - 49`: **MEDIUM** (Minor configuration hygiene issues, advisory findings)
- `50 - 74`: **HIGH** (Missing fundamental security boundaries, expiring certs, suspicious authentication telemetry)
- `75 - 100`: **CRITICAL** (Active incidents, severe protocol weaknesses, confirmed breaches/brute-force)

### Positive Contributors (+Risk)
| Category | Condition | Impact | Rationale |
| :--- | :--- | :--- | :--- |
| **Exposure** | Internet-facing web application | `+15` | External attack surface exposure |
| **Finding** | Expired or Invalid SSL/TLS Certificate | `+30` | Direct MITM risk, broken transport trust |
| **Finding** | Certificate Expiring within 14 days | `+15` | Impending service disruption and trust failure |
| **Finding** | Plaintext HTTP (No HTTPS Redirect) | `+20` | Cleartext eavesdropping risk |
| **Finding** | Missing Strict-Transport-Security (HSTS) | `+10` | Susceptible to SSL-stripping attacks |
| **Finding** | Missing Content-Security-Policy (CSP) | `+10` | Increased blast radius for XSS/data exfiltration |
| **Finding** | Missing Clickjacking Protection (X-Frame-Options) | `+8` | Susceptible to framing & UI redressing |
| **Finding** | Missing X-Content-Type-Options: nosniff | `+5` | MIME-confusion attack vector |
| **Finding** | Sensitive Server Banner Disclosure | `+5` | Assists adversary reconnaissance |
| **Telemetry** | Suspicious Authentication Spike (>= 5 failed attempts) | `+15` | Credential attack or unauthorized access attempt |
| **Incident** | Active Correlated Incident | `+25` | Unresolved active threat state |

### Mitigating Contributors (-Risk)
| Factor | Condition | Impact | Rationale |
| :--- | :--- | :--- | :--- |
| **HSTS Preload & Long Max-Age** | HSTS max-age >= 31536000 with includeSubDomains | `-5` | Strong defense-in-depth transport protection |
| **Strict CSP Present** | Non-trivial Content-Security-Policy deployed | `-5` | Proactive client-side injection defense |
| **Zero Active Incidents** | Verified clean incident history for 14+ days | `-5` | Demonstrates sustained operational stability |

## Audit Log Integration
Each risk calculation output returns:
```json
{
  "asset_id": "ast_9941a8",
  "score": 68,
  "level": "HIGH",
  "reasons": [
    { "factor": "Internet-facing asset exposure", "delta": "+15", "source": "asset_metadata" },
    { "factor": "Missing Strict-Transport-Security header", "delta": "+10", "source": "finding_f01a" },
    { "factor": "Missing Content-Security-Policy header", "delta": "+10", "source": "finding_f01b" },
    { "factor": "Missing X-Frame-Options header", "delta": "+8", "source": "finding_f01c" },
    { "factor": "Suspicious authentication spike (12 failures)", "delta": "+15", "source": "detection_det09" },
    { "factor": "Asset Baseline", "delta": "+10", "source": "system" }
  ]
}
```
