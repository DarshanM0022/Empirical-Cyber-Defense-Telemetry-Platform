from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Float, Text
from sqlalchemy.orm import relationship

from backend.app.core.database import Base
from backend.app.core.time import utcnow

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True)
    asset_id = Column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False) # tls-configuration, security-headers, information-disclosure, cookie-flags
    severity = Column(String(32), nullable=False) # info, low, medium, high, critical
    status = Column(String(32), nullable=False, default="observed") # observed, suspected, confirmed, resolved
    confidence = Column(String(32), nullable=False, default="high") # high, medium, low
    scanner_version = Column(String(32), nullable=False, default="0.1.0")
    source = Column(String(128), nullable=False, default="aegisx-safe-scanner")
    recommendation = Column(Text, nullable=False)
    cve_id = Column(String(64), nullable=True)
    cvss_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    asset = relationship("Asset", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    evidence = relationship("FindingEvidence", back_populates="finding", uselist=False, cascade="all, delete-orphan")

class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    id = Column(String(64), primary_key=True, index=True)
    finding_id = Column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    request_method = Column(String(16), nullable=True)
    request_url = Column(String(512), nullable=True)
    request_headers = Column(Text, nullable=True) # JSON format
    response_status_code = Column(Integer, nullable=True)
    response_headers = Column(Text, nullable=True) # JSON format
    response_body_sample = Column(Text, nullable=True)
    certificate_details = Column(Text, nullable=True) # JSON format
    evidence_sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    finding = relationship("Finding", back_populates="evidence")
