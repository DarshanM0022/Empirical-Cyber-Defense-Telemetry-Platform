from sqlalchemy import Column, String, DateTime, Text

from backend.app.core.database import Base
from backend.app.core.time import utcnow

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)
    actor = Column(String(128), nullable=False)
    action = Column(String(128), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=False)
    details = Column(Text, nullable=True) # JSON details
