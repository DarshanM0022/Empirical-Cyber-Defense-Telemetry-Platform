from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.core.database import get_db
from backend.app.models.asset import Asset
from backend.app.models.finding import Finding
from backend.app.models.event import Detection, Event
from backend.app.models.incident import Incident
from backend.app.models.risk import RiskScore
from backend.app.schemas.risk import RiskScoreResponse
from backend.app.risk.engine import RiskEngine

router = APIRouter(prefix="/risk", tags=["Risk Engine"])

@router.get("/assets/{asset_id}", response_model=RiskScoreResponse)
def get_asset_risk(asset_id: str, db: Session = Depends(get_db)):
    latest_score = db.query(RiskScore).filter(
        RiskScore.asset_id == asset_id
    ).order_by(RiskScore.calculated_at.desc()).first()

    if not latest_score:
        engine = RiskEngine(db)
        latest_score = engine.calculate_asset_risk(asset_id)

    return latest_score

@router.post("/assets/{asset_id}/recalculate", response_model=RiskScoreResponse)
def recalculate_asset_risk(asset_id: str, db: Session = Depends(get_db)):
    engine = RiskEngine(db)
    return engine.calculate_asset_risk(asset_id)

@router.get("/overview")
def get_security_posture_overview(db: Session = Depends(get_db)):
    total_assets = db.query(Asset).count()
    critical_findings = db.query(Finding).filter(
        Finding.severity == "critical",
        Finding.status.in_(["observed", "confirmed"])
    ).count()
    high_findings = db.query(Finding).filter(
        Finding.severity == "high",
        Finding.status.in_(["observed", "confirmed"])
    ).count()

    active_incidents = db.query(Incident).filter(
        Incident.status.in_(["open", "investigating"])
    ).count()

    # Calculate average posture score across all registered assets
    latest_scores = []
    assets = db.query(Asset).all()
    for a in assets:
        sc = db.query(RiskScore).filter(RiskScore.asset_id == a.id).order_by(RiskScore.calculated_at.desc()).first()
        if sc:
            latest_scores.append(sc.score)

    avg_score = round(sum(latest_scores) / len(latest_scores)) if latest_scores else 10
    high_risk_assets = sum(1 for s in latest_scores if s >= 50)

    if avg_score >= 75:
        posture_level = "CRITICAL"
    elif avg_score >= 50:
        posture_level = "HIGH"
    elif avg_score >= 25:
        posture_level = "MEDIUM"
    else:
        posture_level = "LOW"

    suspicious_events = db.query(Detection).count()

    return {
        "overall_risk_score": avg_score,
        "overall_risk_level": posture_level,
        "total_assets": total_assets,
        "high_risk_assets": high_risk_assets,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "active_incidents": active_incidents,
        "suspicious_events": suspicious_events
    }
