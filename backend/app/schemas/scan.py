from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class ScanCreate(BaseModel):
    asset_id: str = Field(..., example="ast_123456")
    scan_type: str = Field(default="web_security_audit", example="web_security_audit")

class ScanResponse(BaseModel):
    id: str
    asset_id: str
    scan_type: str
    status: str
    requests_made: int
    findings_count: int
    duration_seconds: float
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True
