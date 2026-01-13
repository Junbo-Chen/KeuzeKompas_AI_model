import os
import re
import string
import random
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from nltk.corpus import stopwords
import nltk
from typing import List, Optional
from fastapi import HTTPException, status

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
    
    def __init__(self):
        # Woorden die we willen negeren omdat ze weinig betekenis hebben
        self.ignore_words = DUTCH_STOPWORDS | {
            "het", "een", "van", "met", "voor", "mijn",
            "aan", "uit", "over", "door", "bij", "als", "wat", "wie", "hoe", "niet", "wel", "dan",
            "maar", "toch", "ook", "nog", "alleen", "zij", "hij", "student",
            "leren", "geleerd", "leren", "ontwikkeling", "ontwikkelen",
            "ervaring", "ervaringen", "competentie", "competenties","opleiding",
            "werk", "werken", "werkzaamheden", "proces",
            "project", "projecten", "casus", "casussen", "cases",
            "belangrijk", "positief", "negatief", "mogelijk", "mogelijkheden",
            "mogelijkheid", "impact", "betekenis", "betekent", "waarde",
            "focus", "gericht", "actief", "actieve", "nieuwe", "actueel",
            "openstaan", "zelf", "eigen",
            "denken", "doen", "maken", "kiezen", "kies", "vinden",
            "vind", "gaan", "kun", "kan", "zullen", "worden",
            "you", "your", "are", "will", "what", "then", "like", "choose",
            "interested", "experience", "experiencing",
            "learning", "thinking",
            "and", "the", "for", "with", "from", "about",            "hbo", "urban", "veiligheid", "test", "concept",
            "bouwen", "gebouwde", "materiaal", "materialen",
            "leven", "druk", "manieren", "kijken"
        }
        
        self.keep_short = {
            "ai", "it", "bi", "ml", "vr", "ar", "ux", "ui", "qa",
            "pr",
            "hr", "er",
            "gz", "gg",
            "bt", "tv"
        }

        self.punc_remover = str.maketrans("", "", string.punctuation + "“”‘’")
    
    def clean(self, text: str) -> str:
        if not isinstance(text, str):
            return ""
        
        text = text.lower().translate(self.punc_remover)
        text = re.sub(r"\d+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        tokens = text.split()

        filtered_tokens = [
            w for w in tokens
            if (w not in self.ignore_words) and (len(w) > 2 or w in self.keep_short)
        ]

        return " ".join(filtered_tokens)

class ModuleRecommender:
    def __init__(self, csv_path: str = None):
        if csv_path is None:
            csv_path = os.getenv("DATA_PATH", "app/Uitgebreide_VKM_dataset_cleaned.csv")
        
        self.df = pd.read_csv(csv_path)
        self.cleaner = TextCleaner()
        
        self.df['combined_text'] = (
            self.df['name'].fillna('') + ' ' + 
            self.df['shortdescription'].fillna('')
        ).apply(self.cleaner.clean)
        
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 1),  
            max_df=0.8,  
            min_df=2   
        )
        
        self.module_vectors = self.vectorizer.fit_transform(self.df['combined_text'])
        self.term_list = self.vectorizer.get_feature_names_out()

    def find_matches(
        self,
        student_input: str,
        max_results: int = 5,
        filter_options: Optional[dict] = None
    ) -> pd.DataFrame:

        validate_bio(student_input)

        # 1. Pas filters toe
        filtered_modules = self._apply_filters(filter_options)
        if filtered_modules.empty:
            return self._empty_result()

        # 2. Maak een vector van het studentenprofiel
        cleaned_text = self.cleaner.clean(student_input)
        student_vector = self.vectorizer.transform([cleaned_text])

        # 3. Bereken cosine similarity tussen student en modules
        module_indices = filtered_modules.index.to_numpy()
        module_vectors = self.module_vectors[module_indices]
        similarity_scores = cosine_similarity(student_vector, module_vectors).flatten()

        # 4. Selecteer de beste N resultaten
        n_select = min(max_results, len(similarity_scores))
        top_indices = np.argpartition(similarity_scores, -n_select)[-n_select:]
        top_indices = top_indices[np.argsort(similarity_scores[top_indices])[::-1]]

        # 5. Bouw resultatenlijst
        recommendations = []
        for i in top_indices:
            module_idx = module_indices[i]
            module_info = filtered_modules.loc[module_idx]

            # Vind gemeenschappelijke woorden
            common_terms = self._extract_common_terms(student_vector, module_vectors[i])

            # Genereer uitleg
            explanation_text = self._generate_reason(common_terms, module_info['name'], similarity_scores[i])

            # Voeg module toe aan resultaten
            recommendations.append({
                'id': module_info['id'],
                'name': module_info['name'],
                'similarity': similarity_scores[i],
                'location': module_info.get('location'),
                'studycredit': module_info.get('studycredit'),
                'level': module_info.get('level'),
                'overeenkomende_termen': common_terms,
                'reason': explanation_text
            })

        return pd.DataFrame(recommendations)
    
    def _apply_filters(self, filters: dict = None) -> pd.DataFrame:
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
        
        if 'periods' in filters and filters['periods']:
            if 'start_date' in df.columns:
                df['start_date'] = pd.to_datetime(df['start_date'], format="%m/%d/%Y", errors="coerce")


            period_map = {
                '1': 9,
                '2': 10,
                '3': 11,
                '4': 12
            }

            months = [period_map[p] for p in filters['periods'] if p in period_map]

            if months:
                df = df[df['start_date'].dt.month.isin(months)]

        
        return df
    
    def _extract_common_terms(self, student_vector, module_vector, max_terms: int = 6) -> List[str]:
        # Vind indices van woorden die voorkomen in beide vectoren
        student_words_idx = set(student_vector.nonzero()[1])
        module_words_idx = set(module_vector.nonzero()[1])

        shared_idx = student_words_idx.intersection(module_words_idx)
        if not shared_idx:
            return []

        # Bereken scores per gedeeld woord
        scored_words = [(i, module_vector[0, i]) for i in shared_idx]

        # Sorteer aflopend op score
        scored_words.sort(key=lambda x: x[1], reverse=True)

        top_words = [self.term_list[i] for i, _ in scored_words[:max_terms]]
        return top_words


    def _generate_reason(self, keywords: List[str], mod_name: str, similarity: float) -> str:
        if not keywords:
            return f"De module '{mod_name}' heeft een algemene aansluiting bij je profiel."
        keyword_str = " en ".join(keywords) if len(keywords) <= 2 else ", ".join(keywords[:-1]) + f", en {keywords[-1]}"
        if similarity > 0.65:
            options = [
                f"Goede match: '{mod_name}' richt zich op {keyword_str}.",
                f"'{mod_name}' sluit aan bij je focus op {keyword_str}.",
                f"In '{mod_name}' speel {keyword_str} een belangrijke rol."
            ]
        else:
            options = [
                f"'{mod_name}' heeft verband met {keyword_str}.",
                f"Enige overlap gevonden in {keyword_str} voor '{mod_name}'.",
                f"'{mod_name}' raakt thema's aan zoals {keyword_str}."
            ]
        return random.choice(options)
    
    def _empty_result(self) -> pd.DataFrame:
        """Retourneer lege DataFrame met juiste kolommen"""
        return pd.DataFrame(columns=[
            'id', 'name', 'similarity', 'location',
            'studycredit', 'level', 'overeenkomende_termen', 'reason'
        ])

def recommend_modules(
    student_profile: str,
    top_n: int = 5,
    studycredit: Optional[int] = None,
    level: Optional[List[str]] = None,
    locations: Optional[List[str]] = None,
    periods: Optional[List[str]] = None,
) -> pd.DataFrame:
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
    return recommender.find_matches(student_profile, top_n, filters)
