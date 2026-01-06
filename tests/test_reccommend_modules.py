from app.recommend import recommend_modules
import pytest
import pandas as pd
from app.recommend import ModuleRecommender

def test_recommend_modules_rejects_short_profile():
    with pytest.raises(ValueError):
        recommend_modules("te kort")

def test_recommend_modules_returns_dataframe(tmp_path):
    # Maak mini dataset
    data = {
        "id": [1, 2, 3, 4, 5],
        "name": [
            "AI Intro",
            "AI Advanced",
            "Data Analyse",
            "Marketing Basis",
            "UX Design"
        ],
        "shortdescription": [
            "leren werken met ai en data",
            "verdieping in ai en machine learning",
            "data analyseren en visualiseren",
            "leer alles over marketing en branding",
            "gebruikerservaring en ux design"
        ],
        "studycredit": [15, 15, 15, 15, 15],
        "level": ["NLQF6"] * 5,
        "location": ["Breda", "Tilburg", "Breda", "Tilburg", "Breda"],
        "start_date": [
            "2026-10-12",
            "2026-11-01",
            "2026-10-20",
            "2026-12-20",
            "2026-09-15"
        ]
    }
    df = pd.DataFrame(data)

    csv_path = tmp_path / "test.csv"
    df.to_csv(csv_path, index=False)

    recommender = ModuleRecommender(csv_path=str(csv_path))
    result = recommender.find_matches("ik hou van ai", 1)

    assert not result.empty
    assert "name" in result.columns

