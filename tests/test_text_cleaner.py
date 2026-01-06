from app.recommend import TextCleaner

def test_clean_removes_stopwords():
    cleaner = TextCleaner()
    text = "Ik ben een student en ik volg een opleiding"
    cleaned = cleaner.clean(text)

    assert "opleiding" not in cleaned
    assert "student" not in cleaned
    assert "ik" not in cleaned
    assert "een" not in cleaned


def test_clean_keeps_important_short_words():
    cleaner = TextCleaner()
    text = "Ik ben geïnteresseerd in AI en IT"
    cleaned = cleaner.clean(text)

    assert "ai" in cleaned
    assert "it" in cleaned

def test_clean_removes_unimportant_short_words():
    cleaner = TextCleaner()
    text = "Ik wil me oriënteren op de opleiding"
    cleaned = cleaner.clean(text)

    assert "op" not in cleaned
    assert "de" not in cleaned

def test_clean_handles_non_string():
    cleaner = TextCleaner()
    assert cleaner.clean(None) == ""

def test_text_is_lowercased():
    cleaner = TextCleaner()
    text = "IK VIND AI EN UX LEUK"
    
    result = cleaner.clean(text)
    
    assert result == result.lower()

def test_clean_numbers_are_removed():
    cleaner = TextCleaner()
    text = "Ik wil in 2025 werken met AI"
    
    result = cleaner.clean(text)
    
    assert "2025" not in result
    assert any(word.isdigit() for word in result.split()) is False

def test_clean_punctuation_is_removed():
    cleaner = TextCleaner()
    text = "AI, UX & data-science!"
    
    result = cleaner.clean(text)
    
    assert "," not in result
    assert "!" not in result
    assert "&" not in result

def test_clean_empty_string():
    cleaner = TextCleaner()
    assert cleaner.clean("") == ""

