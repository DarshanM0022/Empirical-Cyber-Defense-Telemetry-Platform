from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

class AssetBase(BaseModel):
    name: str = Field(..., example="Customer Portal")
    asset_type: str = Field(default="website", example="website") # website, api_endpoint, server, cloud_vm
    target: str = Field(..., example="example.com")
    environment: str = Field(default="production", example="production")
    owner: str = Field(default="security-team", example="security-team")
    criticality: str = Field(default="medium", example="high")

class AssetCreate(AssetBase):
    pass

class AuthorizationRequest(BaseModel):
    scope: str = Field(..., example="https://example.com")
    authorized_by: str = Field(..., example="secops-lead")
    authorization_method: str = Field(default="admin_verified", example="admin_verified")
    notes: Optional[str] = Field(default=None, example="Approved defensive assessment")
    expires_days: int = Field(default=90, ge=1, le=365)

class AuthorizationResponse(BaseModel):
    id: str
    asset_id: str
    scope: str
    status: str
    challenge_token: str
    authorized_by: str
    authorization_method: str
    notes: Optional[str]
    verified_at: Optional[datetime]
    expires_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True

class AssetResponse(AssetBase):
    id: str
    created_at: datetime
    updated_at: datetime
    authorizations: List[AuthorizationResponse] = []

    class Config:
        from_attributes = True
