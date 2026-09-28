import time
import uuid
from datetime import datetime
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.models.asset import Asset, AssetAuthorization
from backend.app.models.scan import Scan
from backend.app.models.finding import Finding, FindingEvidence
from backend.app.models.audit import AuditLog
from backend.app.scanner.tls_inspector import TLSInspector
from backend.app.scanner.http_inspector import HTTPInspector
from backend.app.risk.engine import RiskEngine
from backend.app.core.time import utcnow

class ScannerEngine:
    """AegisX safe defensive scanner engine enforcing strict authorization barriers and evidence provenance."""

    def __init__(self, db: Session):
        self.db = db
        self.tls_inspector = TLSInspector()
        self.http_inspector = HTTPInspector()

    def run_scan(self, asset_id: str, scan_id: Optional[str] = None, scan_type: str = "web_security_audit") -> Scan:
        asset = self.db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset '{asset_id}' does not exist.")

        # Initialize or retrieve Scan record
        if not scan_id:
            scan = Scan(
                id=f"scn_{uuid.uuid4().hex[:12]}",
                asset_id=asset_id,
                scan_type=scan_type,
                status="pending",
                created_at=utcnow()
            )
            self.db.add(scan)
            self.db.commit()
            self.db.refresh(scan)
        else:
            scan = self.db.query(Scan).filter(Scan.id == scan_id).first()

        # HARD REQUIREMENT: Authorization Verification Gate
        active_auth = self.db.query(AssetAuthorization).filter(
            AssetAuthorization.asset_id == asset_id,
            AssetAuthorization.status == "verified",
            AssetAuthorization.expires_at > utcnow()
        ).first()

        if not active_auth:
            scan.status = "rejected_unauthorized"
            scan.error_message = (
                "Scan aborted: Asset lacks active verified authorization. "
                "In AegisX, scans are strictly prohibited on unauthorized infrastructure."
            )
            scan.completed_at = utcnow()
            self.db.commit()

            # Record security audit log
            self._log_audit(
                actor="aegisx-scanner",
                action="scan_rejected_unauthorized",
                resource_type="asset",
                resource_id=asset_id,
                details=f"Scan {scan.id} rejected due to missing verified authorization."
            )
            return scan

        # Execute Safe Scan
        scan.status = "running"
        scan.started_at = utcnow()
        self.db.commit()

        start_time = time.time()
        total_requests = 0
        all_findings = []

        try:
            # 1. TLS/SSL Inspection
            tls_findings, tls_meta = self.tls_inspector.inspect(asset.target)
            all_findings.extend(tls_findings)
            if tls_meta.get("tls_enabled"):
                total_requests += 1

            # 2. HTTP & Security Headers Inspection
            http_findings, http_requests = self.http_inspector.inspect(asset.target)
            all_findings.extend(http_findings)
            total_requests += http_requests

            # Persist Findings and Evidence
            for f_data in all_findings:
                finding_id = f"fnd_{uuid.uuid4().hex[:12]}"
                evidence_artifact = f_data["evidence"]

                finding = Finding(
                    id=finding_id,
                    asset_id=asset.id,
                    scan_id=scan.id,
                    title=f_data["title"],
                    category=f_data["category"],
                    severity=f_data["severity"],
                    status=f_data.get("status", "observed"),
                    confidence=f_data.get("confidence", "high"),
                    scanner_version="0.1.0",
                    source="aegisx-safe-scanner",
                    recommendation=f_data["recommendation"],
                    created_at=utcnow()
                )
                self.db.add(finding)

                evidence_dict = evidence_artifact.to_dict()
                evidence_record = FindingEvidence(
                    id=f"evd_{uuid.uuid4().hex[:12]}",
                    finding_id=finding_id,
                    timestamp=evidence_dict["timestamp"],
                    request_method=evidence_dict["request_method"],
                    request_url=evidence_dict["request_url"],
                    request_headers=evidence_dict["request_headers"],
                    response_status_code=evidence_dict["response_status_code"],
                    response_headers=evidence_dict["response_headers"],
                    response_body_sample=evidence_dict["response_body_sample"],
                    certificate_details=evidence_dict["certificate_details"],
                    evidence_sha256=evidence_dict["evidence_sha256"],
                    created_at=utcnow()
                )
                self.db.add(evidence_record)

            scan.status = "completed"
            scan.requests_made = total_requests
            scan.findings_count = len(all_findings)
            scan.duration_seconds = round(time.time() - start_time, 2)
            scan.completed_at = utcnow()
            self.db.commit()

            # Trigger automated auditable risk recalculation
            risk_engine = RiskEngine(self.db)
            risk_engine.calculate_asset_risk(asset.id)

            self._log_audit(
                actor="aegisx-scanner",
                action="scan_completed",
                resource_type="asset",
                resource_id=asset.id,
                details=f"Scan {scan.id} completed. {len(all_findings)} findings identified with empirical evidence."
            )

        except Exception as e:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.duration_seconds = round(time.time() - start_time, 2)
            scan.completed_at = utcnow()
            self.db.commit()

        return scan

    def _log_audit(self, actor: str, action: str, resource_type: str, resource_id: str, details: str):
        audit = AuditLog(
            id=f"adt_{uuid.uuid4().hex[:12]}",
            timestamp=utcnow(),
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details
        )
        self.db.add(audit)
        self.db.commit()
