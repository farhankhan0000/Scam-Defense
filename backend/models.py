from sqlalchemy import Column, Float, Integer, String, Boolean, DateTime
from datetime import datetime, timezone
from database import Base

class ScrapedInfo(Base):
    __tablename__ = "scraped_text"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False, unique=True, index=True)
    scraped_text = Column(String, nullable=True)