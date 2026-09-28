import json
from datetime import datetime
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.asset import Asset
from backend.app.models.scan import Scan
from backend.app.models.finding import Finding
from backend.app.models.risk import RiskScore
from backend.app.core.time import utcnow

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/assets/{asset_id}/json")
def get_asset_audit_report_json(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    scans = db.query(Scan).filter(Scan.asset_id == asset_id).order_by(Scan.created_at.desc()).all()
    findings = db.query(Finding).filter(Finding.asset_id == asset_id).order_by(Finding.created_at.desc()).all()
    latest_risk = db.query(RiskScore).filter(RiskScore.asset_id == asset_id).order_by(RiskScore.calculated_at.desc()).first()

    report_payload = {
        "report_metadata": {
            "title": "AegisX Security Audit Assessment Report",
            "generated_at": utcnow().isoformat(),
            "platform_version": "0.1.0",
            "evidence_integrity_policy": "NO_INVENTED_SECURITY_EVENTS",
            "disclaimer": "All findings produced via authorized empirical socket and HTTP inspection."
        },
        "asset": {
            "id": asset.id,
            "name": asset.name,
            "target": asset.target,
            "environment": asset.environment,
            "owner": asset.owner,
            "criticality": asset.criticality,
            "authorizations": [
                {
                    "scope": a.scope,
                    "status": a.status,
                    "authorized_by": a.authorized_by,
                    "method": a.authorization_method,
                    "expires_at": a.expires_at.isoformat()
                } for a in asset.authorizations
            ]
        },
        "risk_posture": {
            "score": latest_risk.score if latest_risk else 10,
            "level": latest_risk.level if latest_risk else "LOW",
            "factors": [
                {
                    "factor": f.factor_name,
                    "delta": f.delta,
                    "source": f.source,
                    "rationale": f.rationale
                } for f in (latest_risk.factors if latest_risk else [])
            ]
        },
        "scans": [
            {
                "id": s.id,
                "type": s.scan_type,
                "status": s.status,
                "requests_made": s.requests_made,
                "findings_count": s.findings_count,
                "duration_seconds": s.duration_seconds,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None
            } for s in scans
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "status": f.status,
                "confidence": f.confidence,
                "recommendation": f.recommendation,
                "evidence": {
                    "timestamp": f.evidence.timestamp.isoformat() if f.evidence else None,
                    "request_url": f.evidence.request_url if f.evidence else None,
                    "response_status": f.evidence.response_status_code if f.evidence else None,
                    "evidence_sha256": f.evidence.evidence_sha256 if f.evidence else None,
                    "raw_response_headers": json.loads(f.evidence.response_headers) if (f.evidence and f.evidence.response_headers) else {}
                } if f.evidence else None
            } for f in findings
        ]
    }
    return report_payload

@router.get("/assets/{asset_id}/html", response_class=HTMLResponse)
def get_asset_audit_report_html(asset_id: str, db: Session = Depends(get_db)):
    data = get_asset_audit_report_json(asset_id, db)
    asset = data["asset"]
    risk = data["risk_posture"]
    findings = data["findings"]

    findings_rows = ""
    for f in findings:
        sha = f['evidence']['evidence_sha256'][:16] + "..." if f.get('evidence') and f['evidence'].get('evidence_sha256') else "N/A"
        findings_rows += f"""
        <tr>
            <td><strong>{f['title']}</strong><br><small style="color:#666;">{f['category']}</small></td>
            <td><span class="badge {f['severity']}">{f['severity'].upper()}</span></td>
            <td>{f['confidence'].capitalize()}</td>
            <td><code>{sha}</code></td>
            <td>{f['recommendation']}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AegisX Security Assessment - {asset['name']}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; margin: 0; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 32px; border: 1px solid #334155; }}
            h1, h2, h3 {{ color: #38bdf8; margin-top: 0; }}
            .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
            .badge.critical {{ background: #dc2626; color: white; }}
            .badge.high {{ background: #ea580c; color: white; }}
            .badge.medium {{ background: #d97706; color: white; }}
            .badge.low {{ background: #2563eb; color: white; }}
            .score-card {{ background: #0f172a; border-radius: 8px; padding: 20px; border-left: 6px solid #38bdf8; margin-bottom: 24px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }}
            th {{ background: #0f172a; color: #94a3b8; }}
            code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #a5f3fc; font-family: monospace; }}
            .meta {{ color: #94a3b8; font-size: 14px; margin-bottom: 24px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>AegisX Defensive Security Assessment</h1>
            <div class="meta">
                <strong>Target:</strong> {asset['target']} | <strong>Asset ID:</strong> {asset['id']} | <strong>Generated:</strong> {data['report_metadata']['generated_at']}
            </div>

            <div class="score-card">
                <h2>Asset Posture: {risk['level']} (Score: {risk['score']}/100)</h2>
                <p>Auditable score calculated empirically from {len(findings)} findings and operational posture.</p>
            </div>

            <h2>Verifiable Security Findings ({len(findings)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Finding</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Evidence SHA-256</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows if findings_rows else "<tr><td colspan='5'>No security findings identified. All evaluated parameters passed.</td></tr>"}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
