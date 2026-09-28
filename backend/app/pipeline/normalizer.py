import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.models.event import Event
from backend.app.schemas.event import EventIngest
from backend.app.core.time import utcnow

class EventNormalizer:
    """Normalizes heterogenous security telemetry into standardized ECS-aligned event schemas."""

    def __init__(self, db: Session):
        self.db = db

    def normalize_and_store(self, event_data: EventIngest) -> Event:
        event = Event(
            id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=event_data.timestamp or utcnow(),
            source=event_data.source.lower().strip(),
            event_type=event_data.event_type.lower().strip(),
            action=event_data.action.lower().strip(),
            actor_type=event_data.actor_type.lower().strip(),
            actor_id=event_data.actor_id.strip(),
            device_id=event_data.device_id.strip() if event_data.device_id else None,
            is_new_device=event_data.is_new_device,
            source_ip=event_data.source_ip.strip() if event_data.source_ip else None,
            result=event_data.result.lower().strip(),
            raw_payload=event_data.raw_payload,
            asset_id=event_data.asset_id,
            created_at=utcnow()
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event
