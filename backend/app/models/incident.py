from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from backend.app.core.database import Base
from backend.app.core.time import utcnow

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    asset_id = Column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="medium") # low, medium, high, critical
    status = Column(String(32), nullable=False, default="open") # open, investigating, contained, resolved, closed
    related_finding_id = Column(String(64), nullable=True)
    summary = Column(Text, nullable=False)
    recommended_actions = Column(Text, nullable=True)
    first_observed_at = Column(DateTime, default=utcnow, nullable=False)
    last_observed_at = Column(DateTime, default=utcnow, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    asset = relationship("Asset", back_populates="incidents")
    detections = relationship("Detection", back_populates="incident")
