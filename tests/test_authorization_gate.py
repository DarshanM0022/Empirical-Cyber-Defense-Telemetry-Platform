import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.asset import Asset, AssetAuthorization
from backend.app.models.scan import Scan
from backend.app.models.audit import AuditLog
from backend.app.scanner.engine import ScannerEngine
from backend.app.core.time import utcnow

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_scanner_strictly_rejects_unauthorized_asset(db_session):
    """
    CRITICAL SECURITY INVARIANT:
    The scanner must actively refuse to transmit packets to any target that lacks
    a verified, active authorization record.
    """
    # 1. Register asset without authorization
    asset = Asset(
        id="ast_test_unauth_01",
        name="Unauthorized Target",
        asset_type="website",
        target="unauthorized-target.internal",
        environment="production",
        owner="unverified",
        criticality="high",
        created_at=utcnow()
    )
    db_session.add(asset)
    db_session.commit()

    # 2. Attempt to run scan
    engine = ScannerEngine(db_session)
    scan = engine.run_scan(asset_id=asset.id)

    # 3. Assert scan was rejected before executing any network probes
    assert scan.status == "rejected_unauthorized"
    assert "Scan aborted: Asset lacks active verified authorization" in scan.error_message
    assert scan.requests_made == 0
    assert scan.findings_count == 0

    # 4. Assert audit trail logged this security rejection
    audit = db_session.query(AuditLog).filter(
        AuditLog.action == "scan_rejected_unauthorized",
        AuditLog.resource_id == asset.id
    ).first()
    assert audit is not None
    assert "rejected due to missing verified authorization" in audit.details

def test_scanner_rejects_expired_authorization(db_session):
    """Verifies that expired authorizations do not grant scan privileges."""
    asset = Asset(
        id="ast_test_expired_01",
        name="Expired Auth Target",
        asset_type="website",
        target="expired.internal",
        environment="staging",
        owner="qa-team",
        criticality="medium",
        created_at=utcnow()
    )
    db_session.add(asset)

    # Authorization that expired yesterday
    expired_auth = AssetAuthorization(
        id="auth_expired_01",
        asset_id=asset.id,
        scope="https://expired.internal",
        status="verified",
        challenge_token="aegisx-token-expired",
        authorized_by="secops-lead",
        authorization_method="admin_verified",
        expires_at=utcnow() - timedelta(days=1),
        created_at=utcnow() - timedelta(days=90)
    )
    db_session.add(expired_auth)
    db_session.commit()

    engine = ScannerEngine(db_session)
    scan = engine.run_scan(asset_id=asset.id)

    assert scan.status == "rejected_unauthorized"
    assert scan.requests_made == 0
