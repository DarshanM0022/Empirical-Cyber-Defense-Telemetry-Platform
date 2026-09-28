from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Boolean, Text
from sqlalchemy.orm import relationship

from backend.app.core.database import Base
from backend.app.core.time import utcnow

class Event(Base):
    __tablename__ = "events"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)
    source = Column(String(64), nullable=False) # identity-provider, endpoint-agent, web-server, firewall
    event_type = Column(String(64), nullable=False) # authentication, network_access, process_execution
    action = Column(String(64), nullable=False) # login, sudo, file_access, connection
    actor_type = Column(String(32), default="user", nullable=False)
    actor_id = Column(String(128), nullable=False, index=True)
    device_id = Column(String(128), nullable=True)
    is_new_device = Column(Boolean, default=False, nullable=False)
    source_ip = Column(String(64), nullable=True)
    result = Column(String(32), nullable=False) # success, failure
    raw_payload = Column(Text, nullable=True)
    asset_id = Column(String(64), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class Detection(Base):
    __tablename__ = "detections"

    id = Column(String(64), primary_key=True, index=True)
    rule_name = Column(String(128), nullable=False, index=True)
    severity = Column(String(32), nullable=False) # low, medium, high, critical
    description = Column(Text, nullable=False)
    event_count = Column(Integer, default=1, nullable=False)
    trigger_details = Column(Text, nullable=False) # JSON details
    asset_id = Column(String(64), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    incident = relationship("Incident", back_populates="detections")
