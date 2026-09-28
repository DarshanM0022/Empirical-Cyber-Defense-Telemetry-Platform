import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.models.asset import Asset
from backend.app.models.finding import Finding
from backend.app.models.event import Event, Detection
from backend.app.models.incident import Incident
from backend.app.models.risk import RiskScore, RiskFactor
from backend.app.core.time import utcnow

class RiskEngine:
    """Transparent, auditable risk scoring engine with deterministic factor attribution."""

    def __init__(self, db: Session):
        self.db = db

    def calculate_asset_risk(self, asset_id: str) -> RiskScore:
        asset = self.db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset '{asset_id}' not found.")

        factors: List[Dict[str, Any]] = []
        current_score = 10 # Baseline score

        factors.append({
            "name": "Asset Baseline Exposure",
            "delta": 10,
            "source": "system",
            "rationale": "Standard baseline risk for an active network asset."
        })

        # 1. Environment & Criticality Exposure
        if asset.environment.lower() == "production":
            factors.append({
                "name": "Production Environment Exposure",
                "delta": 10,
                "source": "asset_configuration",
                "rationale": "Production workloads carry higher operational and security impact."
            })
            current_score += 10

        if asset.criticality.lower() in ("high", "critical"):
            criticality_delta = 15 if asset.criticality.lower() == "critical" else 10
            factors.append({
                "name": f"Asset Criticality ({asset.criticality.capitalize()})",
                "delta": criticality_delta,
                "source": "asset_configuration",
                "rationale": f"High business importance multiplies security exposure."
            })
            current_score += criticality_delta

        # 2. Findings Analysis
        findings = self.db.query(Finding).filter(
            Finding.asset_id == asset_id,
            Finding.status.in_(["observed", "confirmed"])
        ).all()

        hsts_present = True
        csp_present = True

        for f in findings:
            if f.severity == "critical":
                factors.append({
                    "name": f"Critical Finding: {f.title}",
                    "delta": 25,
                    "source": f"finding_{f.id}",
                    "rationale": "Severe vulnerability or trust breakdown directly observable."
                })
                current_score += 25
            elif f.severity == "high":
                factors.append({
                    "name": f"High Severity Finding: {f.title}",
                    "delta": 15,
                    "source": f"finding_{f.id}",
                    "rationale": "Significant defensive gap requiring remediation."
                })
                current_score += 15
            elif f.severity == "medium":
                factors.append({
                    "name": f"Medium Severity Finding: {f.title}",
                    "delta": 8,
                    "source": f"finding_{f.id}",
                    "rationale": "Defensive hardening deficiency."
                })
                current_score += 8
            elif f.severity == "low":
                factors.append({
                    "name": f"Low Severity Finding: {f.title}",
                    "delta": 3,
                    "source": f"finding_{f.id}",
                    "rationale": "Minor configuration advisory."
                })
                current_score += 3

            if "Missing HTTP Strict-Transport-Security" in f.title:
                hsts_present = False
            if "Missing Content-Security-Policy" in f.title:
                csp_present = False

        # 3. Compensating Security Controls (-Risk)
        if len(findings) > 0:
            if hsts_present:
                factors.append({
                    "name": "Compensating Control: HSTS Deployed",
                    "delta": -5,
                    "source": "defensive_control",
                    "rationale": "Strict transport security mitigates SSL-stripping and downgrade attacks."
                })
                current_score -= 5

            if csp_present:
                factors.append({
                    "name": "Compensating Control: Content-Security-Policy Present",
                    "delta": -5,
                    "source": "defensive_control",
                    "rationale": "Content security policy restricts unauthorized script injection."
                })
                current_score -= 5

        # 4. Telemetry Detections & Suspicious Events (Past 24 Hours)
        since_time = utcnow() - timedelta(hours=24)
        recent_detections = self.db.query(Detection).filter(
            Detection.asset_id == asset_id,
            Detection.created_at >= since_time
        ).all()

        for det in recent_detections:
            det_delta = 15 if det.severity in ("high", "critical") else 8
            factors.append({
                "name": f"Security Detection: {det.rule_name}",
                "delta": det_delta,
                "source": f"detection_{det.id}",
                "rationale": det.description
            })
            current_score += det_delta

        # 5. Active Incidents
        active_incidents = self.db.query(Incident).filter(
            Incident.asset_id == asset_id,
            Incident.status.in_(["open", "investigating"])
        ).all()

        for inc in active_incidents:
            factors.append({
                "name": f"Active Incident: {inc.title}",
                "delta": 20,
                "source": f"incident_{inc.id}",
                "rationale": "Unresolved security incident currently undergoing investigation."
            })
            current_score += 20

        # Boundary clamping to [0, 100]
        final_score = max(0, min(100, current_score))

        # Risk level categorization
        if final_score >= 75:
            level = "CRITICAL"
        elif final_score >= 50:
            level = "HIGH"
        elif final_score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Record new RiskScore and RiskFactors
        risk_score = RiskScore(
            id=f"rsk_{uuid.uuid4().hex[:12]}",
            asset_id=asset_id,
            score=final_score,
            level=level,
            calculated_at=utcnow()
        )
        self.db.add(risk_score)
        self.db.flush()

        for f in factors:
            factor_record = RiskFactor(
                id=f"rf_{uuid.uuid4().hex[:12]}",
                risk_score_id=risk_score.id,
                factor_name=f["name"],
                delta=f["delta"],
                source=f["source"],
                rationale=f["rationale"]
            )
            self.db.add(factor_record)

        self.db.commit()
        return risk_score
