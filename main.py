import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
from recommend import recommend_modules 

app = FastAPI()

class StudentProfile(BaseModel):
    bio: str
    periods: List[str] = []
    locations: List[str] = []
    studycredit: Optional[int] = None
    level: Optional[List[str]] = None

@app.post("/recommend")
def get_recommendations(profile: StudentProfile):
    recs = recommend_modules(
        student_profile=profile.bio,
        top_n=5,
        studycredit=profile.studycredit,
        level=profile.level,
        locations=profile.locations,
        periods=profile.periods,
    )
    return recs.to_dict(orient="records")