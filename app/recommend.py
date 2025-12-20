import os
import re
import string
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from nltk.corpus import stopwords 
import nltk
import random
from typing import List, Optional
from fastapi import HTTPException

try:
    DUTCH_STOPWORDS = set(stopwords.words("dutch"))
except LookupError:
    nltk.download("stopwords")
    DUTCH_STOPWORDS = set(stopwords.words("dutch"))

# Optioneel: extra domein-specifieke "ruiswoorden"
EXTRA_NOISE = {
    # Algemene Nederlandse stopwoorden (extra)
    "bij", "voor", "met", "door", "zonder", "over", "onder", "tegen",
    "tussen", "na", "vooraf", "achter", "tijdens", "binnen", "buiten",

    # Onderwijs / studiecontext
    "school", "opleiding", "opleidingen", "module", "modules",
    "keuzemodule", "minor", "programma", "leerjaar", "jaar",
    "week", "periode", "semester", "studie", "studies",
    "student", "studenten", "leerling", "leerlingen",
    "docent", "docenten", "les", "lessen",

    # Leren & ontwikkelen (vaak leeg in betekenis)
    "leren", "geleerd", "leren", "ontwikkeling", "ontwikkelen",
    "verdieping", "kennis", "vaardigheid", "vaardigheden",
    "ervaring", "ervaringen", "competentie", "competenties",
    "theorie", "praktijk", "praktische", "inhoudelijk",

    # Project / werk / stage
    "werk", "werken", "werkzaamheden", "proces",
    "project", "projecten", "casus", "casussen", "cases",
    "stage", "stages", "stageplek", "stageschool",
    "opdracht", "opdrachten",

    # Algemene vaagheid / marketingtaal
    "belangrijk", "positief", "negatief", "mogelijk", "mogelijkheden",
    "mogelijkheid", "impact", "betekenis", "betekent", "waarde",
    "focus", "gericht", "actief", "actieve", "nieuwe", "actueel",

    # Gedrag / houding
    "openstaan", "samen", "samenwerken", "zelf", "eigen",
    "denken", "doen", "maken", "kiezen", "kies", "vinden",
    "vind", "gaan", "kun", "kan", "zullen", "worden",

    # Contextwoorden
    "omgeving", "context", "situatie", "praktische",
    "brede", "complexe", "diverse", "verschillende",

    # Engels (veel voorkomend ruis)
    "you", "your", "are", "will", "what", "then", "like", "choose",
    "interested", "experience", "experiencing",
    "learning", "thinking",
    "and", "the", "for", "with", "from", "about",

    # Overig
    "hbo", "urban", "veiligheid", "test", "concept",
    "bouwen", "gebouwde", "materiaal", "materialen",
    "yellow", "belt", "serious",
    "leven", "druk", "manieren", "kijken"
}

SHORT_TERM_ALLOWLIST = {
    # Technologie & data
    "ai", "it", "bi", "ml", "vr", "ar", "ux", "ui", "qa",

    # Media / communicatie / creatief
    "pr",

    # Organisatie / mens / maatschappij
    "hr", "er",

    # Zorg & welzijn
    "gz", "gg",

    # Economie / recht
    "bt", "tv"
    }

TEXT_STOPWORDS = DUTCH_STOPWORDS | EXTRA_NOISE

PUNCT_TABLE = str.maketrans("", "", string.punctuation + "’‘“”´`")
def prepare_text_for_matching(text: str) -> str:
    """
    Maakt tekst klaar voor matching:
    - lowercase
    - verwijder punctuation
    - verwijder cijfers
    - verwijder NL stopwoorden (+ extra noise)
    """
    if not isinstance(text, str):
        return ""
    
    # lowercasing
    text = text.lower()
    
    # punctuation verwijderen
    text = text.translate(PUNCT_TABLE)
    
    # cijfers eruit
    text = re.sub(r"\d+", " ", text)
    
    # meerdere spaties
    text = re.sub(r"\s+", " ", text).strip()
    
    # stopwoorden filteren
    tokens = []
    for tok in text.split():
        if tok in TEXT_STOPWORDS:
            continue

        # Houd belangrijke korte termen
        if len(tok) <= 2 and tok not in SHORT_TERM_ALLOWLIST:
            continue

        tokens.append(tok)

    
    return " ".join(tokens)

# Laad de dataset
DATA_PATH = os.getenv("DATA_PATH", "app/Uitgebreide_VKM_dataset_cleaned.csv")
df = pd.read_csv(DATA_PATH)

# Verwachte kolommen (minimaal):
# id, name, shortdescription, module_tags, ...
# We maken/overschrijven een 'combined_text'-kolom op basis van relevante velden.

df['combined_text'] = (
    df['name'].fillna('') + ' ' +
    df['shortdescription'].fillna('') 
).apply(prepare_text_for_matching)

# Vectorizer fitten op de complete dataset
vectorizer = TfidfVectorizer(
    ngram_range=(1, 1),  # alleen unigrams
    max_df=0.8,      # woorden die te vaak voorkomen eruit (>80% van de docs)
    min_df=2,        # woorden die maar 1x voorkomen eruit
)
X = vectorizer.fit_transform(df["combined_text"])

FEATURE_NAMES = vectorizer.get_feature_names_out()

def validate_bio(text: str):
    if not re.match(r"^[\w\s\-\.,!?]+$", text, re.UNICODE):
        raise HTTPException(status_code=400, detail="Invalid characters in bio")

def _format_term_list(terms: List[str]) -> str:
    """
    Maak een nette NL opsomming:
    - 'A'
    - 'A' en 'B'
    - 'A', 'B' en 'C'
    """
    if not terms:
        return ""
    if len(terms) == 1:
        return f"'{terms[0]}'"
    if len(terms) == 2:
        return f"'{terms[0]}' en '{terms[1]}'"
    # 3 of meer
    quoted = [f"'{t}'" for t in terms]
    hoofd = ", ".join(quoted[:-1])
    laatste = quoted[-1]
    return f"{hoofd} en {laatste}"

def build_reason(match_terms: List[str], module_name: Optional[str] = None, score: Optional[float] = None) -> str:
    """
    Genereer een uitleg waarom de module past.
    - match_terms: termen waarop je matcht (interesses / keywords)
    """
    terms_str = _format_term_list(match_terms)

    if score >= 0.8:
        kwalificatie = "erg goed"
    elif score >= 0.6:
        kwalificatie = "goed"
    else:
        kwalificatie = "redelijk"

    # Geen specifieke termen: algemene uitleg
    if not match_terms:
        templates = [
            "Deze module sluit {kwalificatie} aan bij je interesses op basis van tekstuele overeenkomsten.",
        ]
    else:
        # Met match_terms
        if module_name:
            templates = [
                "Je interesse in {terms} komt duidelijk terug in '{module}', waardoor deze module {kwalificatie} bij je aansluit.",
                "Omdat {terms} centraal staan in '{module}', past deze module {kwalificatie} bij jouw interesses.",
                "In '{module}' komen {terms} aan bod, wat goed aansluit bij jouw interesses."
            ]
        else:
            templates = [
                "Deze module sluit {kwalificatie} aan bij je interesses in {terms}.",
                "Omdat {terms} in deze module aan bod komen, lijkt deze {kwalificatie} bij je te passen.",
            ]

    template = random.choice(templates)
    return template.format(
        kwalificatie=kwalificatie,
        terms=terms_str,
        module=module_name if module_name else ""
    )

def extract_match_terms(student_vec, module_vec, feature_names, max_terms: int = 8) -> List[str]:
    """
    Welke kernwoorden zowel in de studentvector als in de modulevector voorkomen.
    """
    # indices waar de vector niet 0 is
    student_idx = set(student_vec.nonzero()[1])
    module_idx = set(module_vec.nonzero()[1])

    shared_idx = sorted(student_idx & module_idx)
    terms = [feature_names[i] for i in shared_idx]

    return terms[:max_terms]

def recommend_modules(
    student_profile: str,
    top_n: int = 5,
    studycredit: Optional[int] = None,
    level: Optional[List[str]] = None,
    locations: Optional[List[str]] = None,
    periods: Optional[List[str]] = None,
) -> pd.DataFrame:
    """
    Geeft top 5 modules voor een studentprofiel,
    inclusief:
    - similarity (werkelijke cosine score)
    - match_terms
    - reason (duidelijk-uitleg)
    """
    validate_bio(student_profile)

    # Start met volledige df
    filtered_df = df.copy()

    # Filter op studiepunten
    if studycredit is not None:
        filtered_df = filtered_df[filtered_df["studycredit"] == studycredit]

    # Filter op level
    if level:
        filtered_df = filtered_df[filtered_df["level"].isin(level)]

    # Filter op locaties (any match)
    if locations:
        filtered_df = filtered_df[
            filtered_df["location"].apply(lambda x: any(l.lower() in str(x).lower() for l in locations))
        ]

    # Filter op periods (map '1'->'2026-09' etc.)
    if periods:
        period_map = {
            '1': '2026-09',
            '2': '2026-10',
            '3': '2026-11',
            '4': '2026-12'
        }
        period_prefixes = [period_map.get(p, '') for p in periods if p in period_map]
        if period_prefixes:
            filtered_df = filtered_df[
                filtered_df["start_date"].str.startswith(tuple(period_prefixes))
            ]

    # Niks over? Return lege tabel met juiste kolommen
    if filtered_df.empty:
        return pd.DataFrame(
            columns=[
                "id", "name", "similarity",
                "location", "studycredit",
                "level", "match_terms", "reason"
            ]
        )

    # Studentprofiel vectoriseren
    clean_profile = prepare_text_for_matching(student_profile)
    student_vec = vectorizer.transform([clean_profile])

    # Bijbehorende rijen uit X pakken
    row_indices = filtered_df.index.to_numpy()
    X_filtered = X[row_indices]

    # Cosine similarity
    sims = cosine_similarity(student_vec, X_filtered).flatten()

    # In kopie wegschrijven
    filtered_df = filtered_df.copy()
    filtered_df["similarity"] = sims

    # Sorteren en top N pakken
    top = filtered_df.sort_values("similarity", ascending=False).head(top_n)

    match_terms_list: List[List[str]] = []
    reasons: List[str] = []

    for idx in top.index:
        # positie van deze rij binnen X_filtered
        pos = np.where(row_indices == idx)[0][0]
        module_vec = X_filtered[pos]

        terms = extract_match_terms(student_vec, module_vec, FEATURE_NAMES)
        match_terms_list.append(terms)

        reasons.append(
            build_reason(
                terms,
                module_name=top.at[idx, "name"],
                score=top.at[idx, "similarity"] 
            )
        )

    # Kolommen selecteren en verrijken
    top = top[["id", "name", "similarity", "location", "studycredit", "level"]].copy()
    top["match_terms"] = match_terms_list
    top["reason"] = reasons

    return top.reset_index(drop=True)