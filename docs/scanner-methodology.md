# AegisX Safe Scanner Methodology

## 1. Safety Guardrails & Principles
AegisX adheres strictly to non-destructive, safe testing methodologies aligned with **OWASP Web Security Testing Guide (WSTG)** standards.

- **No Exploitation**: The scanner observes headers, certificates, configurations, and protocol attributes. It does not perform SQL injections, memory corruption tests, fuzzing crashes, or credential stuffing.
- **Strict Authorization Verification**: Before any TCP handshake or HTTP probe is performed, the scanner queries the authorization database. If the target's verification status is not `verified` or has passed `expires_at`, the scan is rejected with code `AUTHORIZATION_REQUIRED`.

## 2. Tested Vectors & Evidence Criteria

### A. TLS/SSL Inspection
- **Protocol Handshake**: Connects to the host SNI on port 443 with TLS 1.2 and TLS 1.3 contexts.
- **Certificate Verification**:
  - Validates chain against standard system CA store.
  - Checks Subject Alternative Names (SAN) matching hostname.
  - Evaluates remaining days until expiration (flags expiring in <= 30 days or already expired).
  - Inspects negotiated cipher suite and version.
- **Evidence Stored**: Issuer CN, Subject CN, SAN list, Valid-From/To ISO timestamps, negotiated cipher name, protocol version, serial number.

### B. HTTP & Security Headers Inspection
- **HTTPS Enforcement**: Sends an HTTP request to port 80 to verify HTTP-to-HTTPS redirect (`301`/`308` redirect with `Location` starting with `https://`).
- **HTTP Strict Transport Security (HSTS)**:
  - Checks presence of `Strict-Transport-Security`.
  - Verifies `max-age` (warns if missing or under 15768000 / 6 months).
- **Content-Security-Policy (CSP)**:
  - Checks presence of `Content-Security-Policy`.
  - Analyzes for dangerous flags like `unsafe-inline` or missing default-src.
- **Clickjacking & MIME Protection**:
  - Checks `X-Frame-Options` (`DENY` or `SAMEORIGIN`) or CSP `frame-ancestors`.
  - Checks `X-Content-Type-Options: nosniff`.
- **Referrer Policy & Permissions Policy**:
  - Checks `Referrer-Policy` and `Permissions-Policy`.
- **Information Disclosure in Response Headers**:
  - Identifies server fingerprinting (`Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4.3`, `X-AspNet-Version`).
- **Cookie Security Flags**:
  - Validates `Set-Cookie` directives for `Secure`, `HttpOnly`, and `SameSite` (`Strict` / `Lax`).

## 3. Finding Confidence Levels
- **Observed**: A configuration setting or header is directly missing or present in the raw network response. (Confidence: High, Empirical).
- **Suspected**: A banner or indicator hints at potential vulnerability but requires further context.
- **Confirmed**: Verified condition with deterministic evidence and zero ambiguity.
