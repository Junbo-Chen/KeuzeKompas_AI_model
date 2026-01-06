import os
import re
import string
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from nltk.corpus import stopwords
import nltk
from typing import List, Optional
from fastapi import HTTPException

# Download Nederlandse stopwoorden
try:
    DUTCH_STOPWORDS = set(stopwords.words("dutch"))
except LookupError:
    nltk.download("stopwords")
    DUTCH_STOPWORDS = set(stopwords.words("dutch"))

def validate_bio(text: str):
    if not re.match(r"^[\w\s\-\.,!?]+$", text, re.UNICODE):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid input detected"
        )
        
class TextCleaner:
    """Maakt tekst schoon voor analyse"""
    
    def __init__(self):
        # Woorden die we willen negeren omdat ze weinig betekenis hebben
        self.ignore_words = DUTCH_STOPWORDS | {
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
        
        # Belangrijke korte woorden die we WEL willen behouden
        self.keep_short = {
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
        
        # Voor punctuatie verwijdering
        self.punct_table = str.maketrans("", "", string.punctuation + "’‘“”´`")
    
    def clean(self, text: str) -> str:
        """Maak tekst schoon en retourneer belangrijke woorden"""
        if not isinstance(text, str):
            return ""
        
        # Stap 1: Alles naar lowercase
        text = text.lower()
        
        # Stap 2: Verwijder punctuatie
        text = text.translate(self.punct_table)
        
        # Stap 3: Verwijder cijfers
        text = re.sub(r"\d+", " ", text)
        
        # Stap 4: Normaliseer spaties
        text = re.sub(r"\s+", " ", text).strip()
        
        # Stap 5: Filter woorden
        words = []
        for word in text.split():
            # Skip stopwoorden
            if word in self.ignore_words:
                continue
            # Skip korte woorden tenzij belangrijk
            if len(word) <= 2 and word not in self.keep_short:
                continue
            words.append(word)
        
        return " ".join(words)


class ModuleRecommender:
    """Hoofdklasse voor module aanbevelingen"""
    
    def __init__(self, csv_path: str = None):
        # Laad data
        if csv_path is None:
            csv_path = os.getenv("DATA_PATH", "app/Uitgebreide_VKM_dataset_cleaned.csv")
        
        self.df = pd.read_csv(csv_path)
        self.cleaner = TextCleaner()
        
        # Maak schone tekst voor elke module
        self.df['clean_text'] = (
            self.df['name'].fillna('') + ' ' + 
            self.df['shortdescription'].fillna('')
        ).apply(self.cleaner.clean)
        
        # Maak TF-IDF vectorizer en fit op modules
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 1),  # Alleen losse woorden
            max_df=0.8,          # Negeer woorden in >80% van modules
            min_df=2             # Negeer woorden die maar 1x voorkomen
        )
        
        self.module_vectors = self.vectorizer.fit_transform(self.df['clean_text'])
        self.vocab = self.vectorizer.get_feature_names_out()
    
    def find_matches(
        self,
        student_text: str,
        n_results: int = 5,
        filters: dict = None
    ) -> pd.DataFrame:
        """
        Vind de beste matches voor een student.
        
        Args:
            student_text: Wat de student interessant vindt
            n_results: Hoeveel resultaten terug te geven
            filters: Dict met filters zoals {'studycredit': 5, 'level': ['propedeuse']}
        
        Returns:
            DataFrame met aanbevelingen
        """
        validate_bio(student_text)
        
        # Stap 1: Filter modules indien nodig
        filtered_df = self._apply_filters(filters)
        
        if filtered_df.empty:
            return self._empty_result()
        
        # Stap 2: Vectoriseer student profiel
        clean_student = self.cleaner.clean(student_text)
        student_vec = self.vectorizer.transform([clean_student])
        
        # Stap 3: Bereken similarity scores
        indices = filtered_df.index.to_numpy()
        module_vecs = self.module_vectors[indices]
        scores = cosine_similarity(student_vec, module_vecs).flatten()
        
        # Stap 4: Selecteer top N
        top_n = min(n_results, len(scores))
        best_indices = np.argpartition(scores, -top_n)[-top_n:]
        best_indices = best_indices[np.argsort(scores[best_indices])[::-1]]
        
        # Stap 5: Bouw resultaat
        results = []
        for idx in best_indices:
            original_idx = indices[idx]
            module = filtered_df.loc[original_idx]
            
            # Vind gedeelde woorden
            shared_words = self._find_shared_words(student_vec, module_vecs[idx])
            
            # Maak uitleg
            explanation = self._make_explanation(
                shared_words, 
                module['name'],
                scores[idx]
            )
            
            results.append({
                'id': module['id'],
                'name': module['name'],
                'similarity': scores[idx],
                'location': module.get('location'),
                'studycredit': module.get('studycredit'),
                'level': module.get('level'),
                'match_terms': shared_words,
                'reason': explanation
            })
        
        return pd.DataFrame(results)
    
    def _apply_filters(self, filters: dict = None) -> pd.DataFrame:
        """Pas filters toe op de dataset"""
        df = self.df.copy()
        
        if not filters:
            return df
        
        # Filter op studiepunten
        if 'studycredit' in filters and filters['studycredit']:
            df = df[df['studycredit'] == filters['studycredit']]
        
        # Filter op niveau
        if 'level' in filters and filters['level']:
            df = df[df['level'].isin(filters['level'])]
        
        # Filter op locatie
        if 'locations' in filters and filters['locations']:
            mask = df['location'].apply(
                lambda x: any(loc.lower() in str(x).lower() 
                            for loc in filters['locations'])
            )
            df = df[mask]
        
        # Filter op periode
        if 'periods' in filters and filters['periods']:
            period_map = {
                '1': '2026-09', '2': '2026-10',
                '3': '2026-11', '4': '2026-12'
            }
            prefixes = [period_map.get(p) for p in filters['periods'] if p in period_map]
            if prefixes:
                df = df[df['start_date'].str.startswith(tuple(prefixes))]
        
        return df
    
    def _find_shared_words(self, student_vec, module_vec, max_words: int = 6) -> List[str]:
        """Vind woorden die in beide vectoren voorkomen"""
        # Indices waar beide vectoren niet-nul zijn
        student_idx = set(student_vec.nonzero()[1])
        module_idx = set(module_vec.nonzero()[1])
        
        # Gedeelde indices
        shared = student_idx & module_idx
        
        if not shared:
            return []
        
        # Sorteer op module score en neem top N
        word_scores = [(i, module_vec[0, i]) for i in shared]
        word_scores.sort(key=lambda x: x[1], reverse=True)
        
        return [self.vocab[i] for i, _ in word_scores[:max_words]]
    
    def _make_explanation(self, words: List[str], module_name: str, score: float) -> str:
        """Genereer uitleg waarom deze module past"""
        # Bepaal kwalificatie op basis van score
        if score >= 0.8:
            quality = "uitstekend"
        elif score >= 0.6:
            quality = "goed"
        else:
            quality = "redelijk"
        
        # Geen specifieke woorden gevonden
        if not words:
            return f"Deze module sluit {quality} aan bij je profiel."
        
        # Maak lijst van woorden leesbaar
        if len(words) == 1:
            word_text = words[0]
        elif len(words) == 2:
            word_text = f"{words[0]} en {words[1]}"
        else:
            word_text = ", ".join(words[:-1]) + f" en {words[-1]}"
        
        # Kies een template
        templates = [
            f"De thema's {word_text} komen terug in '{module_name}', wat {quality} bij je past.",
            f"'{module_name}' behandelt {word_text}, waardoor deze module {quality} aansluit.",
            f"Op basis van {word_text} lijkt '{module_name}' {quality} bij je profiel te passen."
        ]
        
        # Kies semi-random (maar consistent voor dezelfde score)
        template_idx = int(score * 10) % len(templates)
        return templates[template_idx]
    
    def _empty_result(self) -> pd.DataFrame:
        """Retourneer lege DataFrame met juiste kolommen"""
        return pd.DataFrame(columns=[
            'id', 'name', 'similarity', 'location',
            'studycredit', 'level', 'match_terms', 'reason'
        ])

def recommend_modules(
    student_profile: str,
    top_n: int = 5,
    studycredit: Optional[int] = None,
    level: Optional[List[str]] = None,
    locations: Optional[List[str]] = None,
    periods: Optional[List[str]] = None,
) -> pd.DataFrame:
    """
    Vind beste modules voor een student.
    
    Voorbeeld gebruik:
        results = recommend_modules(
            student_profile="Ik vind programmeren en AI interessant",
            top_n=5,
            studycredit=5,
            level=['propedeuse']
        )
    """
    # Validatie
    if not student_profile or len(student_profile.strip()) < 10:
        raise ValueError("Student profiel moet minimaal 10 karakters bevatten")
    
    # Bouw filters dict
    filters = {}
    if studycredit is not None:
        filters['studycredit'] = studycredit
    if level:
        filters['level'] = level
    if locations:
        filters['locations'] = locations
    if periods:
        filters['periods'] = periods
    
    # Maak recommender en vind matches
    recommender = ModuleRecommender()
    return recommender.find_matches(student_profile, top_n, filters or None)
