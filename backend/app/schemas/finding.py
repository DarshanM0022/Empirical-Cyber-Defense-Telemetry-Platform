from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class FindingEvidenceResponse(BaseModel):
    id: str
    finding_id: str
    timestamp: datetime
    request_method: Optional[str] = None
    request_url: Optional[str] = None
    request_headers: Optional[str] = None
    response_status_code: Optional[int] = None
    response_headers: Optional[str] = None
    response_body_sample: Optional[str] = None
    certificate_details: Optional[str] = None
    evidence_sha256: str
    created_at: datetime

    class Config:
        from_attributes = True

class FindingResponse(BaseModel):
    id: str
    asset_id: str
    scan_id: str
    title: str
    category: str
    severity: str
    status: str
    confidence: str
    scanner_version: str
    source: str
    recommendation: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    created_at: datetime
    evidence: Optional[FindingEvidenceResponse] = None

    class Config:
        from_attributes = True
