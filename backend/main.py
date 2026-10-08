from pydantic import BaseModel
from fastapi import FastAPI, Depends
from database import engine, get_db
import models
from sqlalchemy.orm import Session
from heuristics import testing_url


app = FastAPI(title="Phishing Defence API")

models.Base.metadata.create_all(bind=engine)


@app.get("/")
def health_check(db: Session=Depends(get_db)):
    return {
        "status": "active",
        "message": "FastAPI is running and database session is active."
    }

class URLRequest(BaseModel):
    test_url: str


@app.post("/scam")
def get_url_results(request_data: URLRequest):

    heuristic_result = testing_url(request_data.test_url)
    base_score = heuristic_result["final_score"]
    threats = heuristic_result["threat_reasons"]

    if base_score < 25:
        return {"status" : "Safe", "score" : base_score, "reasons" : threats}

    elif base_score > 70:
        return {"status" : "Phishing", "score" : base_score, "reasons" : threats}

    else:
        return "ai"

