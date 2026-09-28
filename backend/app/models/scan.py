from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Float, Text
from sqlalchemy.orm import relationship

from backend.app.core.database import Base
from backend.app.core.time import utcnow

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    asset_id = Column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_type = Column(String(64), nullable=False, default="web_security_audit")
    status = Column(String(32), nullable=False, default="pending") # pending, running, completed, failed, rejected_unauthorized
    requests_made = Column(Integer, default=0, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    duration_seconds = Column(Float, default=0.0, nullable=False)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    asset = relationship("Asset", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
