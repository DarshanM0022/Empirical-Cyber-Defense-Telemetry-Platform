import hashlib
import hmac
import secrets
from typing import Dict, Any

def generate_evidence_hash(data: str) -> str:
    """Computes SHA-256 hash for raw evidence preservation and audit provenance."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def generate_verification_token() -> str:
    """Generates a cryptographically strong challenge token for asset authorization."""
    return f"aegisx-challenge-{secrets.token_hex(16)}"

def verify_token(provided_token: str, expected_token: str) -> bool:
    """Timing-attack-safe comparison of verification tokens."""
    return hmac.compare_digest(provided_token, expected_token)
