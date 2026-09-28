from datetime import datetime, timezone

def utcnow() -> datetime:
    """Returns timezone-naive UTC datetime compatible with standard SQL databases without deprecation warnings."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
