from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

class IncidentResponse(BaseModel):
    id: str
    title: str
    asset_id: str
    severity: str
    status: str
    related_finding_id: Optional[str]
    summary: str
    recommended_actions: Optional[str]
    first_observed_at: datetime
    last_observed_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True

class IncidentUpdate(BaseModel):
    status: Optional[str] = Field(None, example="contained") # open, investigating, contained, resolved, closed
    recommended_actions: Optional[str] = None
