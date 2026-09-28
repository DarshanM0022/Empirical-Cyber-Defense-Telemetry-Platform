from datetime import datetime
from typing import List
from pydantic import BaseModel

class RiskFactorSchema(BaseModel):
    factor_name: str
    delta: int
    source: str
    rationale: str

    class Config:
        from_attributes = True

class RiskScoreResponse(BaseModel):
    asset_id: str
    score: int
    level: str
    calculated_at: datetime
    factors: List[RiskFactorSchema] = []

    class Config:
        from_attributes = True
