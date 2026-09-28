from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship

from backend.app.core.database import Base
from backend.app.core.time import utcnow

class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(String(64), primary_key=True, index=True)
    asset_id = Column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    score = Column(Integer, nullable=False) # 0 - 100
    level = Column(String(32), nullable=False) # low, medium, high, critical
    calculated_at = Column(DateTime, default=utcnow, nullable=False)

    asset = relationship("Asset", back_populates="risk_scores")
    factors = relationship("RiskFactor", back_populates="risk_score", cascade="all, delete-orphan")

class RiskFactor(Base):
    __tablename__ = "risk_factors"

    id = Column(String(64), primary_key=True, index=True)
    risk_score_id = Column(String(64), ForeignKey("risk_scores.id", ondelete="CASCADE"), nullable=False, index=True)
    factor_name = Column(String(255), nullable=False)
    delta = Column(Integer, nullable=False) # e.g. +22, -12
    source = Column(String(128), nullable=False)
    rationale = Column(Text, nullable=False)

    risk_score = relationship("RiskScore", back_populates="factors")
