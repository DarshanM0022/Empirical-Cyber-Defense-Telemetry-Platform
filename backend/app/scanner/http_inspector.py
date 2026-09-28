import httpx
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

from backend.app.core.config import settings
from backend.app.scanner.evidence import EvidenceArtifact

class HTTPInspector:
    """Safe, empirical HTTP and security header inspector complying with OWASP WSTG guidelines."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": settings.SCANNER_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    def inspect(self, host_or_url: str) -> Tuple[List[Dict[str, Any]], int]:
        findings: List[Dict[str, Any]] = []
        requests_made = 0

        target_host = self._normalize_host(host_or_url)
        http_url = f"http://{target_host}/"
        https_url = f"https://{target_host}/"

        res_http = None
        # 1. Test Plaintext HTTP & HTTPS Redirection
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False, verify=False) as client:
                res_http = client.get(http_url, headers=self.headers)
                requests_made += 1

                location = res_http.headers.get("location", "")
                is_redirect_to_https = (res_http.status_code in (301, 302, 307, 308)) and location.startswith("https://")

                if not is_redirect_to_https:
                    evidence = EvidenceArtifact(
                        request_method="GET",
                        request_url=http_url,
                        request_headers=dict(res_http.request.headers),
                        response_status_code=res_http.status_code,
                        response_headers=dict(res_http.headers),
                        response_body_sample=res_http.text[:512]
                    )
                    findings.append({
                        "title": "Plaintext HTTP Service Does Not Enforce HTTPS Redirection",
                        "category": "security-headers",
                        "severity": "medium",
                        "status": "observed",
                        "confidence": "high",
                        "recommendation": "Configure web server to return an immediate HTTP 301 Permanent Redirect to the HTTPS equivalent for all port 80 traffic.",
                        "evidence": evidence
                    })
        except Exception:
            pass

        # 2. Test Primary HTTPS Endpoint (or fallback to HTTP if target only serves HTTP)
        evaluated_response = None
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                res_https = client.get(https_url, headers=self.headers)
                requests_made += 1
                evaluated_response = res_https
        except Exception:
            # If HTTPS is not available on this port/host, analyze the HTTP response
            evaluated_response = res_http

        if evaluated_response is not None:
            self._evaluate_security_headers(evaluated_response, findings)

        return findings, requests_made

    def _evaluate_security_headers(self, res: httpx.Response, findings: List[Dict[str, Any]]):
        res_headers = {k.lower(): v for k, v in res.headers.items()}
        raw_headers = dict(res.headers)

        def make_evidence():
            return EvidenceArtifact(
                request_method="GET",
                request_url=str(res.url),
                request_headers=dict(res.request.headers),
                response_status_code=res.status_code,
                response_headers=raw_headers,
                response_body_sample=res.text[:512]
            )

        # A. Strict-Transport-Security (HSTS)
        hsts = res_headers.get("strict-transport-security")
        if not hsts:
            findings.append({
                "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
                "category": "security-headers",
                "severity": "medium",
                "status": "observed",
                "confidence": "high",
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to enforce HTTPS and prevent SSL-stripping.",
                "evidence": make_evidence()
            })
        elif "max-age" in hsts:
            try:
                parts = [p.strip() for p in hsts.split(";")]
                for p in parts:
                    if p.startswith("max-age="):
                        age_val = int(p.split("=")[1])
                        if age_val < 15768000:
                            findings.append({
                                "title": f"HSTS Header Has Weak Max-Age ({age_val}s)",
                                "category": "security-headers",
                                "severity": "low",
                                "status": "observed",
                                "confidence": "high",
                                "recommendation": "Increase HSTS max-age to at least 31536000 seconds (1 year).",
                                "evidence": make_evidence()
                            })
            except ValueError:
                pass

        # B. Content-Security-Policy (CSP)
        csp = res_headers.get("content-security-policy")
        if not csp:
            findings.append({
                "title": "Missing Content-Security-Policy (CSP) Header",
                "category": "security-headers",
                "severity": "medium",
                "status": "observed",
                "confidence": "high",
                "recommendation": "Define a Content-Security-Policy header specifying allowed sources for scripts, styles, objects, and frames to restrict Cross-Site Scripting (XSS).",
                "evidence": make_evidence()
            })
        else:
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                findings.append({
                    "title": "Content-Security-Policy Uses Insecure Directive (unsafe-inline or unsafe-eval)",
                    "category": "security-headers",
                    "severity": "low",
                    "status": "observed",
                    "confidence": "high",
                    "recommendation": "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives; use nonces or cryptographic hashes instead.",
                    "evidence": make_evidence()
                })

        # C. X-Frame-Options (Clickjacking Protection)
        xfo = res_headers.get("x-frame-options")
        frame_ancestors = "frame-ancestors" in (csp or "")
        if not xfo and not frame_ancestors:
            findings.append({
                "title": "Missing Anti-Clickjacking Header (X-Frame-Options / frame-ancestors)",
                "category": "security-headers",
                "severity": "medium",
                "status": "observed",
                "confidence": "high",
                "recommendation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors' directive to mitigate UI redressing.",
                "evidence": make_evidence()
            })

        # D. X-Content-Type-Options (MIME Confusion)
        xcto = res_headers.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            findings.append({
                "title": "Missing X-Content-Type-Options: nosniff Header",
                "category": "security-headers",
                "severity": "low",
                "status": "observed",
                "confidence": "high",
                "recommendation": "Set 'X-Content-Type-Options: nosniff' to instruct browsers not to override the declared MIME type.",
                "evidence": make_evidence()
            })

        # E. Referrer-Policy
        ref_policy = res_headers.get("referrer-policy")
        if not ref_policy:
            findings.append({
                "title": "Missing Referrer-Policy Header",
                "category": "security-headers",
                "severity": "low",
                "status": "observed",
                "confidence": "high",
                "recommendation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to limit sensitive referrer leakage.",
                "evidence": make_evidence()
            })

        # F. Server & Technology Disclosure
        server_hdr = res_headers.get("server")
        if server_hdr and any(c in server_hdr for c in ["/", "Ubuntu", "Debian", "Apache", "nginx", "Microsoft-IIS"]):
            findings.append({
                "title": f"Server Software Version Disclosed in Header ({server_hdr})",
                "category": "information-disclosure",
                "severity": "low",
                "status": "observed",
                "confidence": "high",
                "recommendation": "Suppress detailed version numbers in the 'Server' response header (e.g. configure ServerTokens Prod in Apache or server_tokens off in Nginx).",
                "evidence": make_evidence()
            })

        x_powered_by = res_headers.get("x-powered-by")
        if x_powered_by:
            findings.append({
                "title": f"Technology Framework Disclosed in X-Powered-By Header ({x_powered_by})",
                "category": "information-disclosure",
                "severity": "low",
                "status": "observed",
                "confidence": "high",
                "recommendation": "Remove or disable the 'X-Powered-By' header in application server configuration to prevent targeted technology exploitation.",
                "evidence": make_evidence()
            })

        # G. Cookie Security Flags
        cookies = res.headers.get_list("set-cookie") if hasattr(res.headers, "get_list") else [res.headers.get("set-cookie")]
        for cookie in [c for c in cookies if c]:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()
            if "secure" not in cookie_lower:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                    "category": "cookie-flags",
                    "severity": "medium",
                    "status": "observed",
                    "confidence": "high",
                    "recommendation": "Append the '; Secure' flag to all Set-Cookie headers so cookies are never transmitted over cleartext channels.",
                    "evidence": make_evidence()
                })
            if "httponly" not in cookie_lower:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                    "category": "cookie-flags",
                    "severity": "low",
                    "status": "observed",
                    "confidence": "high",
                    "recommendation": "Append the '; HttpOnly' flag to prevent access to session cookies via client-side JavaScript.",
                    "evidence": make_evidence()
                })
            if "samesite" not in cookie_lower:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    "category": "cookie-flags",
                    "severity": "low",
                    "status": "observed",
                    "confidence": "high",
                    "recommendation": "Set '; SameSite=Lax' or '; SameSite=Strict' to protect against Cross-Site Request Forgery (CSRF).",
                    "evidence": make_evidence()
                })

    def _normalize_host(self, host_or_url: str) -> str:
        if "://" in host_or_url:
            parsed = urlparse(host_or_url)
            return parsed.netloc or host_or_url
        return host_or_url
