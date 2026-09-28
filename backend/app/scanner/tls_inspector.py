import socket
import ssl
from datetime import datetime
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

from backend.app.scanner.evidence import EvidenceArtifact

class TLSInspector:
    """Safe, non-destructive TLS/SSL inspector performing empirical certificate and protocol checks."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def inspect(self, host_or_url: str, port: int = 443) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        findings = []
        hostname = self._extract_hostname(host_or_url)
        metadata = {"hostname": hostname, "port": port, "tls_enabled": False}

        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    metadata["tls_enabled"] = True
                    cert = ssock.getpeercert()
                    cipher, version, bits = ssock.cipher()
                    protocol = ssock.version()

                    metadata["protocol"] = protocol
                    metadata["cipher"] = cipher
                    metadata["bits"] = bits
                    metadata["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
                    metadata["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))

                    # 1. Certificate Expiration Check
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        metadata["not_after"] = not_after.isoformat()
                        remaining_days = (not_after - datetime.utcnow()).days
                        metadata["remaining_days"] = remaining_days

                        if remaining_days < 0:
                            evidence = EvidenceArtifact(
                                request_url=f"tls://{hostname}:{port}",
                                certificate_details=metadata
                            )
                            findings.append({
                                "title": "SSL/TLS Certificate is Expired",
                                "category": "tls-configuration",
                                "severity": "critical",
                                "status": "confirmed",
                                "confidence": "high",
                                "recommendation": "Renew and install an authorized TLS certificate immediately to prevent browser warnings and MITM susceptibility.",
                                "evidence": evidence
                            })
                        elif remaining_days <= 14:
                            evidence = EvidenceArtifact(
                                request_url=f"tls://{hostname}:{port}",
                                certificate_details=metadata
                            )
                            findings.append({
                                "title": f"SSL/TLS Certificate Expiring Soon ({remaining_days} days remaining)",
                                "category": "tls-configuration",
                                "severity": "high",
                                "status": "observed",
                                "confidence": "high",
                                "recommendation": f"The certificate expires in {remaining_days} days ({not_after_str}). Schedule certificate renewal.",
                                "evidence": evidence
                            })
                        elif remaining_days <= 30:
                            evidence = EvidenceArtifact(
                                request_url=f"tls://{hostname}:{port}",
                                certificate_details=metadata
                            )
                            findings.append({
                                "title": f"SSL/TLS Certificate Renewal Notice ({remaining_days} days remaining)",
                                "category": "tls-configuration",
                                "severity": "medium",
                                "status": "observed",
                                "confidence": "high",
                                "recommendation": "Plan automated renewal for this certificate before it drops below 14 days.",
                                "evidence": evidence
                            })

                    # 2. Protocol configuration check (TLSv1.0 or TLSv1.1)
                    if protocol in ("TLSv1", "TLSv1.1"):
                        evidence = EvidenceArtifact(
                            request_url=f"tls://{hostname}:{port}",
                            certificate_details=metadata
                        )
                        findings.append({
                            "title": f"Deprecated TLS Protocol Version Negotiated ({protocol})",
                            "category": "tls-configuration",
                            "severity": "high",
                            "status": "confirmed",
                            "confidence": "high",
                            "recommendation": "Disable TLS 1.0 and TLS 1.1 in web server configuration. Enforce TLS 1.2 or TLS 1.3 only.",
                            "evidence": evidence
                        })

        except ssl.SSLCertVerificationError as e:
            metadata["error"] = str(e)
            evidence = EvidenceArtifact(
                request_url=f"tls://{hostname}:{port}",
                certificate_details={"error": str(e), "verification": "failed"}
            )
            findings.append({
                "title": f"SSL/TLS Certificate Verification Failed: {e.verify_message}",
                "category": "tls-configuration",
                "severity": "high",
                "status": "confirmed",
                "confidence": "high",
                "recommendation": "Ensure the server presents a valid certificate chain signed by a recognized Certificate Authority matching the hostname.",
                "evidence": evidence
            })
        except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e:
            metadata["error"] = str(e)

        return findings, metadata

    def _extract_hostname(self, host_or_url: str) -> str:
        if "://" in host_or_url:
            parsed = urlparse(host_or_url)
            return parsed.hostname or host_or_url
        return host_or_url.split(":")[0]
