from app.recommend import validate_bio
import pytest

def test_validate_bio_valid():
    validate_bio("Ik hou van data en AI.")

def test_validate_bio_invalid():
    with pytest.raises(Exception):
        validate_bio("<script>alert(1)</script>")

def test_validate_bio_allows_punctuation():
    validate_bio("Ik hou van AI, data-science en UX!")

def test_validate_bio_rejects_emoji():
    with pytest.raises(Exception):
        validate_bio("Ik hou van AI 😊")

