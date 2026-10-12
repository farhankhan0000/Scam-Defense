from click import clear
from pydantic import BaseModel
from fastapi import FastAPI, Depends
from database import engine, get_db
import models
from sqlalchemy.orm import Session
from heuristics import testing_url
from contextlib import asynccontextmanager
import httpx
from agent import calling_agent
import traceback


live_phishing_db = set()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Fetching active thread intelligence feed...")
    try:
        headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64 AppleWebkit/537.36"}
        async with httpx.AsyncClient(follow_redirects=True, headers=headers) as client:
            response = await client.get("https://openphish.com/feed.txt")
            if response.status_code==200:

                raw_urls = response.text.splitlines()
                clean_urls = {url.strip() for url in raw_urls if url.strip()}
                live_phishing_db.update(clean_urls)
                print(f"Loaded {len(live_phishing_db)} malicious URLs into Memory cache.")
            else:
                print(f"Failed to load threat feed! Server returned HTTP {response.status_code}")
    except Exception as e:
        print(f"Failed to load threat field: {e}")

    yield

    live_phishing_db.clear()

app = FastAPI(title="Phishing Defence API", lifespan=lifespan)

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

    try:
        heuristic_result = testing_url(request_data.test_url, live_phishing_db)
        base_score = heuristic_result["final_score"]
        threats = heuristic_result["threat_reasons"]

        if base_score < 25:
            return {"status" : "Safe", "score" : base_score, "reasons" : threats}

        elif base_score > 70:
            return {"status" : "Phishing", "score" : base_score, "reasons" : threats}

        else:
            detection_info = f"URL : {request_data.test_url} , score: {base_score} , reasons: {threats}"
            return calling_agent(detection_info)

    except Exception as e:
        error_details = traceback.format_exc()

        return {"Crash report" : str(e), "Traceback" : error_details}
