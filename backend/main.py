from backend.testing import router as scam_router
from fastapi import FastAPI, Depends
from database import engine, get_db
import models
from sqlalchemy.orm import Session


app = FastAPI(title="Phishing Defence API")

models.Base.metadata.create_all(bind=engine)


app.include_router(scam_router)

@app.get("/")
def health_check(db: Session=Depends(get_db)):
    return {
        "status": "active",
        "message": "FastAPI is running and database session is active."
    }
