from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.asset import Asset
from backend.app.models.event import Event, Detection
from backend.app.models.incident import Incident
from backend.app.schemas.event import EventIngest
from backend.app.pipeline.normalizer import EventNormalizer
from backend.app.pipeline.detection_engine import DetectionEngine
from backend.app.pipeline.correlation import CorrelationEngine
from backend.app.core.time import utcnow

def test_siem_telemetry_and_detection_pipeline():
    """
    Tests SIEM normalization, deterministic detection rules, and incident correlation
    using real event sequences without fabricated anomalies.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # 1. Register test asset
        asset = Asset(
            id="ast_siem_test_01",
            name="Target Portal",
            asset_type="website",
            target="portal.internal",
            environment="production",
            owner="secops",
            criticality="high",
            created_at=utcnow()
        )
        db.add(asset)
        db.commit()

        normalizer = EventNormalizer(db)
        detection_engine = DetectionEngine(db)
        correlation_engine = CorrelationEngine(db)

        # 2. Ingest 4 failed authentication events (under threshold of 5)
        for i in range(4):
            event_dto = EventIngest(
                source="identity-provider",
                event_type="authentication",
                action="login",
                actor_id="user_admin",
                source_ip="198.51.100.12",
                result="failure",
                asset_id=asset.id
            )
            ev = normalizer.normalize_and_store(event_dto)
            dets = detection_engine.evaluate_event(ev)
            assert len(dets) == 0, "No detection should trigger under threshold of 5 failures"

        # 3. Ingest the 5th failed authentication event (hits threshold!)
        fifth_dto = EventIngest(
            source="identity-provider",
            event_type="authentication",
            action="login",
            actor_id="user_admin",
            source_ip="198.51.100.12",
            result="failure",
            asset_id=asset.id
        )
        ev5 = normalizer.normalize_and_store(fifth_dto)
        dets5 = detection_engine.evaluate_event(ev5)

        assert len(dets5) == 1, "Deterministic rule must trigger detection at 5 failures"
        det = dets5[0]
        assert det.rule_name == "brute_force_authentication"
        assert det.severity == "high"
        assert "5 failed authentication attempts observed" in det.description

        # 4. Correlate detection into an Incident
        incident = correlation_engine.correlate_detection(det)
        assert incident is not None
        assert incident.asset_id == asset.id
        assert incident.status == "open"
        assert incident.severity == "high"
        assert "Security Alert: Brute Force Authentication" in incident.title

        # 5. Ingest subsequent SUCCESSFUL login on a NEW DEVICE for the same user
        success_new_dev = EventIngest(
            source="identity-provider",
            event_type="authentication",
            action="login",
            actor_id="user_admin",
            device_id="unrecognized_laptop_99",
            is_new_device=True,
            source_ip="198.51.100.12",
            result="success",
            asset_id=asset.id
        )
        ev_success = normalizer.normalize_and_store(success_new_dev)
        dets_success = detection_engine.evaluate_event(ev_success)

        assert len(dets_success) == 1
        assert dets_success[0].rule_name == "suspicious_new_device_login"

        # 6. Verify total empirical counts in database
        total_auth_events = db.query(Event).filter(Event.actor_id == "user_admin").count()
        failed_count = db.query(Event).filter(Event.actor_id == "user_admin", Event.result == "failure").count()
        new_dev_count = db.query(Event).filter(Event.actor_id == "user_admin", Event.is_new_device == True).count()
        det_count = db.query(Detection).filter(Detection.asset_id == asset.id).count()

        assert total_auth_events == 6
        assert failed_count == 5
        assert new_dev_count == 1
        assert det_count == 2

    finally:
        db.close()
