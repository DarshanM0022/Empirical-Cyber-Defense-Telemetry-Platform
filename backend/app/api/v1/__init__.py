from fastapi import APIRouter

from backend.app.api.v1.assets import router as assets_router
from backend.app.api.v1.scans import router as scans_router
from backend.app.api.v1.findings import router as findings_router
from backend.app.api.v1.events import router as events_router
from backend.app.api.v1.detections import router as detections_router
from backend.app.api.v1.incidents import router as incidents_router
from backend.app.api.v1.risk import router as risk_router
from backend.app.api.v1.reports import router as reports_router
from backend.app.api.v1.audit import router as audit_router

api_router = APIRouter()
api_router.include_router(assets_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
api_router.include_router(events_router)
api_router.include_router(detections_router)
api_router.include_router(incidents_router)
api_router.include_router(risk_router)
api_router.include_router(reports_router)
api_router.include_router(audit_router)
