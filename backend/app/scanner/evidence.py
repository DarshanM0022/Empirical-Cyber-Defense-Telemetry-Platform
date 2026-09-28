import json
from datetime import datetime
from typing import Optional, Dict, Any
from backend.app.core.security import generate_evidence_hash
from backend.app.core.time import utcnow

class EvidenceArtifact:
    def __init__(
        self,
        request_method: Optional[str] = None,
        request_url: Optional[str] = None,
        request_headers: Optional[Dict[str, str]] = None,
        response_status_code: Optional[int] = None,
        response_headers: Optional[Dict[str, str]] = None,
        response_body_sample: Optional[str] = None,
        certificate_details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ):
        self.timestamp = timestamp or utcnow()
        self.request_method = request_method
        self.request_url = request_url
        self.request_headers = request_headers or {}
        self.response_status_code = response_status_code
        self.response_headers = response_headers or {}
        self.response_body_sample = response_body_sample[:1024] if response_body_sample else None
        self.certificate_details = certificate_details or {}

        # Canonical evidence string for SHA-256 generation
        canonical_repr = json.dumps({
            "timestamp": self.timestamp.isoformat(),
            "url": self.request_url,
            "status": self.response_status_code,
            "headers": self.response_headers,
            "certificate": self.certificate_details
        }, sort_keys=True)
        self.evidence_sha256 = generate_evidence_hash(canonical_repr)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "request_method": self.request_method,
            "request_url": self.request_url,
            "request_headers": json.dumps(self.request_headers),
            "response_status_code": self.response_status_code,
            "response_headers": json.dumps(self.response_headers),
            "response_body_sample": self.response_body_sample,
            "certificate_details": json.dumps(self.certificate_details),
            "evidence_sha256": self.evidence_sha256
        }
