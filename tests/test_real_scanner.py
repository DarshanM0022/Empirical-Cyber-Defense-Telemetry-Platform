import threading
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.asset import Asset, AssetAuthorization
from backend.app.models.scan import Scan
from backend.app.models.finding import Finding
from backend.app.scanner.engine import ScannerEngine
from backend.app.scanner.http_inspector import HTTPInspector
from backend.app.core.time import utcnow

class VulnerableRealAppHandler(BaseHTTPRequestHandler):
    """
    Real HTTP request handler designed to test safe defensive scanner discovery.
    Intentionally exposes server banners and omits HSTS / CSP security headers.
    """
    def do_GET(self):
        self.send_response(200)
        # Disclose server banner intentionally for detection
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Insecure cookie missing Secure & HttpOnly
        self.send_header("Set-Cookie", "session_id=abc123xyz; Path=/")
        # Note: No HSTS, No Content-Security-Policy, No X-Frame-Options
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Real Authorized Test Web Application</h1></body></html>")

    def log_message(self, format, *args):
        # Suppress standard logging during automated tests
        return

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def test_real_scanner_against_live_local_http_endpoint():
    """
    REAL WORLD TEST:
    Executes an actual live TCP/HTTP scan against a running local HTTP server.
    Verifies empirical evidence collection, header detection, and SHA-256 provenance.
    """
    port = get_free_port()
    server = HTTPServer(('127.0.0.1', port), VulnerableRealAppHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Run HTTPInspector directly against the real running server
        inspector = HTTPInspector(timeout=5.0)
        findings, requests_made = inspector.inspect(f"127.0.0.1:{port}")

        # Assert real network requests were dispatched and answered
        assert requests_made > 0, "Real network requests must be performed"
        assert len(findings) > 0, "Scanner must detect missing headers on live endpoint"

        # Verify specific empirical findings
        titles = [f["title"] for f in findings]
        
        # 1. Missing HSTS must be detected
        assert any("Missing HTTP Strict-Transport-Security" in t for t in titles)

        # 2. Missing CSP must be detected
        assert any("Missing Content-Security-Policy" in t for t in titles)

        # 3. Missing X-Frame-Options must be detected
        assert any("Missing Anti-Clickjacking Header" in t for t in titles)

        # 4. Server banner disclosure must be detected
        assert any("Server Software Version Disclosed" in t for t in titles)

        # 5. Insecure cookie flags must be detected
        assert any("Missing 'Secure' Flag" in t for t in titles)
        assert any("Missing 'HttpOnly' Flag" in t for t in titles)

        # 6. Verify EVIDENCE INTEGRITY:
        # Every finding must have an EvidenceArtifact with real response headers and SHA-256
        for f in findings:
            evidence = f["evidence"]
            assert evidence.response_headers is not None
            assert "server" in [k.lower() for k in evidence.response_headers.keys()]
            assert len(evidence.evidence_sha256) == 64 # Valid SHA-256 hex digest
            assert f["status"] == "observed" # Empirical observation
            assert f["confidence"] == "high"

    finally:
        server.shutdown()
        server.server_close()

def test_end_to_end_authorized_scan_workflow():
    """
    Tests end-to-end integration: Asset registration -> Verified Authorization ->
    Scanner Engine execution against real local service -> Database persistence.
    """
    port = get_free_port()
    server = HTTPServer(('127.0.0.1', port), VulnerableRealAppHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # In-memory test database
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # 1. Create asset targeting live server
        asset = Asset(
            id="ast_live_test_01",
            name="Authorized Local Live App",
            asset_type="website",
            target=f"127.0.0.1:{port}",
            environment="testing",
            owner="security-team",
            criticality="high",
            created_at=utcnow()
        )
        db.add(asset)

        # 2. Grant verified authorization
        auth = AssetAuthorization(
            id="auth_live_test_01",
            asset_id=asset.id,
            scope=f"http://127.0.0.1:{port}",
            status="verified",
            challenge_token="aegisx-verified-live-token",
            authorized_by="security-lead",
            authorization_method="admin_verified",
            expires_at=utcnow() + timedelta(days=30),
            created_at=utcnow()
        )
        db.add(auth)
        db.commit()

        # 3. Execute scan via ScannerEngine
        scanner_engine = ScannerEngine(db)
        scan = scanner_engine.run_scan(asset_id=asset.id)

        # 4. Verify scan completion and evidence persistence
        assert scan.status == "completed"
        assert scan.requests_made > 0
        assert scan.findings_count > 0
        assert scan.duration_seconds >= 0.0

        # Query persisted findings
        persisted_findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        assert len(persisted_findings) == scan.findings_count

        for f in persisted_findings:
            assert f.evidence is not None
            assert f.evidence.evidence_sha256 is not None
            assert len(f.evidence.evidence_sha256) == 64

    finally:
        db.close()
        server.shutdown()
        server.server_close()
