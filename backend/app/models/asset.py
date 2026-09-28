from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from backend.app.core.database import Base
from backend.app.core.time import utcnow

class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    asset_type = Column(String(64), nullable=False, default="website") # website, api_endpoint, server, cloud_vm
    target = Column(String(512), nullable=False, index=True) # domain or URL or IP
    environment = Column(String(64), nullable=False, default="production") # production, staging, development, testing
    owner = Column(String(128), nullable=False, default="security-team")
    criticality = Column(String(32), nullable=False, default="medium") # low, medium, high, critical
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    authorizations = relationship("AssetAuthorization", back_populates="asset", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    risk_scores = relationship("RiskScore", back_populates="asset", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="asset", cascade="all, delete-orphan")

class AssetAuthorization(Base):
    __tablename__ = "asset_authorizations"

    id = Column(String(64), primary_key=True, index=True)
    asset_id = Column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    scope = Column(String(512), nullable=False)
    status = Column(String(32), nullable=False, default="pending") # pending, verified, revoked, expired
    challenge_token = Column(String(128), nullable=False)
    authorized_by = Column(String(128), nullable=False)
    authorization_method = Column(String(64), nullable=False, default="admin_verified") # admin_verified, dns_txt, http_token
    notes = Column(Text, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    asset = relationship("Asset", back_populates="authorizations")
