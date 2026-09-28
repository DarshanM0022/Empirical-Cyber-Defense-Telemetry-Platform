from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class EventIngest(BaseModel):
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)
    source: str = Field(..., example="identity-provider") # identity-provider, endpoint-agent, web-server, firewall
    event_type: str = Field(..., example="authentication") # authentication, network_access, process_execution
    action: str = Field(..., example="login") # login, sudo, file_access, connection
    actor_type: str = Field(default="user", example="user")
    actor_id: str = Field(..., example="user_123")
    device_id: Optional[str] = Field(default=None, example="device_42")
    is_new_device: bool = Field(default=False)
    source_ip: Optional[str] = Field(default=None, example="192.168.1.50")
    result: str = Field(..., example="failure") # success, failure
    raw_payload: Optional[str] = Field(default=None)
    asset_id: Optional[str] = Field(default=None, example="ast_123456")

class EventResponse(BaseModel):
    id: str
    timestamp: datetime
    source: str
    event_type: str
    action: str
    actor_type: str
    actor_id: str
    device_id: Optional[str]
    is_new_device: bool
    source_ip: Optional[str]
    result: str
    asset_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class DetectionResponse(BaseModel):
    id: str
    rule_name: str
    severity: str
    description: str
    event_count: int
    trigger_details: str
    asset_id: Optional[str]
    incident_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
