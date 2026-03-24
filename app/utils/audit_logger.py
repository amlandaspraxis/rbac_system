from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False)
    resource = Column(String(255), nullable=False)
    details = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def log_action(db: Session, user_id: int, action: str, resource: str, details: str = None):
    """Write an audit log entry."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        details=details,
    )
    db.add(entry)
    db.commit()
