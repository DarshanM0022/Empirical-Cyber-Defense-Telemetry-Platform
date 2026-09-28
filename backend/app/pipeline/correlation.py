import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from backend.app.models.asset import Asset
from backend.app.models.finding import Finding
from backend.app.models.event import Detection
from backend.app.models.incident import Incident
from backend.app.risk.engine import RiskEngine
from backend.app.core.time import utcnow

class CorrelationEngine:
    """Correlates vulnerability findings and detection events into unified, actionable security incidents."""

    def __init__(self, db: Session):
        self.db = db

    def correlate_detection(self, detection: Detection) -> Optional[Incident]:
        if not detection.asset_id:
            return None

        # Check for open incident on this asset
        incident = self.db.query(Incident).filter(
            Incident.asset_id == detection.asset_id,
            Incident.status.in_(["open", "investigating"])
        ).first()

        # If no active incident exists, create one
        if not incident:
            # Correlate with any active findings on the same asset
            related_finding = self.db.query(Finding).filter(
                Finding.asset_id == detection.asset_id,
                Finding.severity.in_(["high", "critical"]),
                Finding.status.in_(["observed", "confirmed"])
            ).first()

            finding_context = f" Correlated with finding: {related_finding.title}." if related_finding else ""

            incident = Incident(
                id=f"inc_{uuid.uuid4().hex[:12]}",
                title=f"Security Alert: {detection.rule_name.replace('_', ' ').title()} on Asset",
                asset_id=detection.asset_id,
                severity=detection.severity,
                status="open",
                related_finding_id=related_finding.id if related_finding else None,
                summary=f"Incident opened automatically. Trigger: {detection.description}.{finding_context}",
                recommended_actions=(
                    "1. Review source IP and authenticate legitimacy of identity actor.\n"
                    "2. Enforce MFA or rotate credentials for affected accounts.\n"
                    "3. Verify defensive controls on target asset."
                ),
                first_observed_at=detection.created_at,
                last_observed_at=detection.created_at,
                created_at=utcnow()
            )
            self.db.add(incident)
            self.db.flush()

        # Link detection to incident
        detection.incident_id = incident.id
        incident.last_observed_at = utcnow()
        self.db.commit()

        # Recalculate asset risk with newly active incident
        risk_engine = RiskEngine(self.db)
        risk_engine.calculate_asset_risk(detection.asset_id)

        return incident
