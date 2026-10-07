from sqlalchemy import Column, Float, Integer, String, Boolean, DateTime, column
from datetime import datetime, timezone
from database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False, unique=True, index=True)

    risk_score = Column(Float, nullable=True)
    ai_summary = Column(String, nullable=False)
    is_phishing = Column(Boolean, default=False)

    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))