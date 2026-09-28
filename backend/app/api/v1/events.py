from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.core.database import get_db
from backend.app.models.event import Event, Detection
from backend.app.models.incident import Incident
from backend.app.schemas.event import EventIngest, EventResponse, DetectionResponse
from backend.app.pipeline.normalizer import EventNormalizer
from backend.app.pipeline.detection_engine import DetectionEngine
from backend.app.pipeline.correlation import CorrelationEngine

router = APIRouter(prefix="/events", tags=["SIEM Events"])

@router.post("", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def ingest_event(payload: EventIngest, db: Session = Depends(get_db)):
    # 1. Normalize and store event
    normalizer = EventNormalizer(db)
    event = normalizer.normalize_and_store(payload)

    # 2. Evaluate deterministic detection rules
    detection_engine = DetectionEngine(db)
    detections = detection_engine.evaluate_event(event)

    # 3. Correlate detections into incidents
    correlation_engine = CorrelationEngine(db)
    created_incidents = []
    for det in detections:
        inc = correlation_engine.correlate_detection(det)
        if inc:
            created_incidents.append(inc.id)

    return {
        "event_id": event.id,
        "status": "ingested",
        "detections_triggered": len(detections),
        "incidents_created_or_updated": len(created_incidents)
    }

@router.get("", response_model=List[EventResponse])
def list_events(
    actor_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(Event)
    if actor_id:
        query = query.filter(Event.actor_id == actor_id)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    return query.order_by(Event.timestamp.desc()).limit(limit).all()

@router.get("/stats")
def get_telemetry_stats(actor_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Provides empirical, non-fabricated event counts derived directly from stored telemetry."""
    base_query = db.query(Event)
    if actor_id:
        base_query = base_query.filter(Event.actor_id == actor_id)

    auth_attempts = base_query.filter(Event.event_type == "authentication").count()
    failed_auth = base_query.filter(Event.event_type == "authentication", Event.result == "failure").count()
    new_device_events = base_query.filter(Event.is_new_device == True).count()

    det_query = db.query(Detection)
    if actor_id:
        det_query = det_query.filter(Detection.trigger_details.contains(actor_id))
    suspicious_detections = det_query.count()

    inc_query = db.query(Incident).filter(Incident.status.in_(["open", "investigating"]))
    active_incidents = inc_query.count()

    return {
        "actor_filter": actor_id or "all_identities",
        "telemetry_counts": {
            "authentication_attempts": auth_attempts,
            "failed_authentication": failed_auth,
            "new_device_events": new_device_events,
            "suspicious_authentication_detections": suspicious_detections,
            "active_incidents": active_incidents
        },
        "description": f"{suspicious_detections} suspicious authentication events detected empirically."
    }
