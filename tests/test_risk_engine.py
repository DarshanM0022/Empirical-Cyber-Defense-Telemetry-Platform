from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.asset import Asset
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.risk.engine import RiskEngine
from backend.app.core.time import utcnow

def test_risk_engine_transparent_calculation():
    """
    Tests that the risk engine produces verifiable mathematical scores with
    explicit, auditable attribution reasons and no magic weights.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # 1. Create baseline asset
        asset = Asset(
            id="ast_risk_test_01",
            name="Core Banking API",
            asset_type="api_endpoint",
            target="api.bank.internal",
            environment="production", # +10
            owner="infra",
            criticality="high", # +10
            created_at=utcnow()
        )
        db.add(asset)
        db.commit()

        risk_engine = RiskEngine(db)
        initial_risk = risk_engine.calculate_asset_risk(asset.id)

        # Baseline (10) + Production (10) + High Criticality (10) = 30 (MEDIUM)
        assert initial_risk.score == 30
        assert initial_risk.level == "MEDIUM"
        assert len(initial_risk.factors) == 3

        # 2. Add Scan and Findings
        scan = Scan(
            id="scn_risk_test_01",
            asset_id=asset.id,
            scan_type="web_security_audit",
            status="completed",
            created_at=utcnow()
        )
        db.add(scan)
        db.commit()

        # Add Critical Finding: Expired TLS Certificate (+25)
        f_critical = Finding(
            id="fnd_crit_01",
            asset_id=asset.id,
            scan_id=scan.id,
            title="SSL/TLS Certificate is Expired",
            category="tls-configuration",
            severity="critical",
            status="confirmed",
            confidence="high",
            recommendation="Renew certificate immediately",
            created_at=utcnow()
        )
        # Add High Finding: Missing HSTS (+15)
        f_high = Finding(
            id="fnd_high_01",
            asset_id=asset.id,
            scan_id=scan.id,
            title="Missing HTTP Strict-Transport-Security (HSTS) Header",
            category="security-headers",
            severity="high",
            status="observed",
            confidence="high",
            recommendation="Deploy HSTS header",
            created_at=utcnow()
        )
        db.add(f_critical)
        db.add(f_high)
        db.commit()

        # 3. Recalculate risk
        updated_risk = risk_engine.calculate_asset_risk(asset.id)

        # 30 (previous) + 25 (critical) + 15 (high) - 5 (compensating control: CSP present) = 65 (HIGH)
        assert updated_risk.score == 65
        assert updated_risk.level == "HIGH"

        # Verify auditable factor explanations
        factor_names = [f.factor_name for f in updated_risk.factors]
        assert any("Asset Baseline" in f for f in factor_names)
        assert any("Production Environment" in f for f in factor_names)
        assert any("Critical Finding" in f for f in factor_names)
        assert any("High Severity Finding" in f for f in factor_names)
        assert any("Compensating Control" in f for f in factor_names)

        # Every factor must have an auditable delta and rationale
        for factor in updated_risk.factors:
            assert factor.delta != 0
            assert factor.rationale is not None
            assert len(factor.rationale) > 5

    finally:
        db.close()
