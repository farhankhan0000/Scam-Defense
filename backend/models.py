from sqlalchemy import Column, Float, Integer, String, Boolean, DateTime
from datetime import datetime, timezone
from database import Base

class AIReport(Base):
    id=Column(Integer, primary_key=True)
    url=Column(String, nullable=False)
    summary=Column(String, nullable=False)