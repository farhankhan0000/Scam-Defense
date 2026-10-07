from backend.testing import router as scam_router
from fastapi import FastAPI, Depends
from database import SessionLocal, engine
import models


app = FastAPI(title="Phishing Defence API")

models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app.include_router(scam_router)
