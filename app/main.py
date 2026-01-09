import os
import logging
from logging.handlers import RotatingFileHandler
import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.recommend import recommend_modules  # Assuming recommend.py is updated as needed
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request

# Load environment variables from .env file
load_dotenv()

# Security: Load API key from env (set in deploy platform)
API_KEY = os.getenv("API_KEY")

# Logging setup: Secure logging to file with rotation (max 5MB, 3 backups)
logger = logging.getLogger("api_logger")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("api.log", maxBytes=5*1024*1024, backupCount=3)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Rate limiter: 100 requests/min per IP
limiter = Limiter(key_func=get_remote_address)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # frontend link
        # backend link
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    # Altijd veilige headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # ❗ Geen CSP voor Swagger / ReDoc
    if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
        return response

    # CSP alleen voor API endpoints
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    return response


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Auth scheme
security = HTTPBearer(auto_error=False)

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key missing"
        )

    if credentials.credentials != API_KEY:
        logger.warning("Invalid API key attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials

class StudentProfile(BaseModel):
    bio: str = Field(..., max_length=2000)  # Limit bio length to prevent abuse
    periods: List[str] = []
    locations: List[str] = []
    studycredit: Optional[int] = None
    level: Optional[List[str]] = None

@app.post("/recommend")
@limiter.limit("100/minute")  # Rate limit
async def get_recommendations(profile: StudentProfile, request: Request, api_key: str = Depends(verify_api_key)):
    try:
        logger.info(f"Processing recommendation for bio: {profile.bio[:50]}...")  # Log partial for privacy
        recs = recommend_modules(
            student_profile=profile.bio,
            top_n=5,
            studycredit=profile.studycredit,
            level=profile.level,
            locations=profile.locations,
            periods=profile.periods,
        )
        return recs.to_dict(orient="records")
    except Exception as e:
        logger.error(f"Error in recommendation: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")