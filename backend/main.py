from backend.testing import router as scam_router
from fastapi import FastAPI


app = FastAPI()

app.include_router(scam_router)
