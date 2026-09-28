import json
import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.models.event import Event, Detection
from backend.app.core.time import utcnow

class DetectionEngine:
    """Deterministic detection engine evaluating empirical telemetry against concrete threshold rules."""

    def __init__(self, db: Session):
        self.db = db

    def evaluate_event(self, current_event: Event) -> List[Detection]:
        detections_triggered: List[Detection] = []

        if current_event.event_type == "authentication":
            # 1. Rule: Brute Force Authentication Threshold
            if current_event.result == "failure":
                bf_detection = self._check_brute_force(current_event)
                if bf_detection:
                    detections_triggered.append(bf_detection)

                spray_detection = self._check_ip_spray(current_event)
                if spray_detection:
                    detections_triggered.append(spray_detection)

            # 2. Rule: Suspicious New Device Login After Failures
            elif current_event.result == "success" and current_event.is_new_device:
                new_dev_detection = self._check_new_device_after_failures(current_event)
                if new_dev_detection:
                    detections_triggered.append(new_dev_detection)

        return detections_triggered

    def _check_brute_force(self, event: Event) -> Optional[Detection]:
        ten_mins_ago = utcnow() - timedelta(minutes=10)
        recent_failures = self.db.query(Event).filter(
            Event.actor_id == event.actor_id,
            Event.event_type == "authentication",
            Event.result == "failure",
            Event.timestamp >= ten_mins_ago
        ).count()

        if recent_failures >= 5:
            # Check if active detection already created within last 5 minutes to avoid spam
            existing = self.db.query(Detection).filter(
                Detection.rule_name == "brute_force_authentication",
                Detection.trigger_details.contains(event.actor_id),
                Detection.created_at >= utcnow() - timedelta(minutes=5)
            ).first()

            if not existing:
                detection = Detection(
                    id=f"det_{uuid.uuid4().hex[:12]}",
                    rule_name="brute_force_authentication",
                    severity="high",
                    description=f"{recent_failures} failed authentication attempts observed for identity '{event.actor_id}' in 10 minutes.",
                    event_count=recent_failures,
                    trigger_details=json.dumps({
                        "actor_id": event.actor_id,
                        "failure_count": recent_failures,
                        "latest_source_ip": event.source_ip,
                        "window_minutes": 10
                    }),
                    asset_id=event.asset_id,
                    created_at=utcnow()
                )
                self.db.add(detection)
                self.db.commit()
                return detection
        return None

    def _check_new_device_after_failures(self, event: Event) -> Optional[Detection]:
        thirty_mins_ago = utcnow() - timedelta(minutes=30)
        recent_failures = self.db.query(Event).filter(
            Event.actor_id == event.actor_id,
            Event.event_type == "authentication",
            Event.result == "failure",
            Event.timestamp >= thirty_mins_ago
        ).count()

        if recent_failures >= 3:
            detection = Detection(
                id=f"det_{uuid.uuid4().hex[:12]}",
                rule_name="suspicious_new_device_login",
                severity="high",
                description=f"Successful login on new device '{event.device_id}' for identity '{event.actor_id}' preceded by {recent_failures} failed attempts.",
                event_count=recent_failures + 1,
                trigger_details=json.dumps({
                    "actor_id": event.actor_id,
                    "device_id": event.device_id,
                    "source_ip": event.source_ip,
                    "preceding_failures": recent_failures
                }),
                asset_id=event.asset_id,
                created_at=utcnow()
            )
            self.db.add(detection)
            self.db.commit()
            return detection
        return None

    def _check_ip_spray(self, event: Event) -> Optional[Detection]:
        if not event.source_ip:
            return None

        fifteen_mins_ago = utcnow() - timedelta(minutes=15)
        distinct_actors = self.db.query(Event.actor_id).filter(
            Event.source_ip == event.source_ip,
            Event.event_type == "authentication",
            Event.result == "failure",
            Event.timestamp >= fifteen_mins_ago
        ).distinct().count()

        if distinct_actors >= 3:
            existing = self.db.query(Detection).filter(
                Detection.rule_name == "ip_credential_spray",
                Detection.trigger_details.contains(event.source_ip),
                Detection.created_at >= utcnow() - timedelta(minutes=5)
            ).first()

            if not existing:
                detection = Detection(
                    id=f"det_{uuid.uuid4().hex[:12]}",
                    rule_name="ip_credential_spray",
                    severity="high",
                    description=f"Possible credential spraying attack: failed authentication attempts targeting {distinct_actors} distinct accounts from source IP '{event.source_ip}'.",
                    event_count=distinct_actors,
                    trigger_details=json.dumps({
                        "source_ip": event.source_ip,
                        "targeted_accounts_count": distinct_actors,
                        "window_minutes": 15
                    }),
                    asset_id=event.asset_id,
                    created_at=utcnow()
                )
                self.db.add(detection)
                self.db.commit()
                return detection
        return None
