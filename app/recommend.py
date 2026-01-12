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
    """Maakt tekst schoon voor analyse"""
    
    def __init__(self):
        # Woorden die we willen negeren omdat ze weinig betekenis hebben
        self.ignore_words = DUTCH_STOPWORDS | {
            "het", "een", "van", "met", "voor", "mijn",
            "aan", "uit", "over", "door", "bij", "als", "wat", "wie", "hoe", "niet", "wel", "dan",
            "maar", "toch", "ook", "nog", "alleen", "zij", "hij", "student",
            # Leren & ontwikkelen (vaak leeg in betekenis)
            "leren", "geleerd", "leren", "ontwikkeling", "ontwikkelen",
            "verdieping", "kennis", "vaardigheid", "vaardigheden",
            "ervaring", "ervaringen", "competentie", "competenties",
            "theorie", "praktijk", "praktische", "inhoudelijk", "opleiding",
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
        """Verwerk tekst naar kernwoorden zonder stopwoorden en irrelevante korte woorden."""
        if not isinstance(text, str):
            return ""
        
        # 1. Alles lowercase en verwijder punctuatie
        text = text.lower()
        text = text.translate(self.punct_table)

        # 2. Verwijder cijfers en extra spaties
        text = re.sub(r"\d+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()

        # 3. Tokenize en filter woorden
        tokens = text.split()
        
        # Filter logica: stopwoorden en korte woorden
        filtered_tokens = [
            w for w in tokens
            if (w not in self.ignore_words) and (len(w) > 2 or w in self.keep_short)
        ]

        # 4. Samenvoegen tot string
        return " ".join(filtered_tokens)

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
        student_input: str,
        max_results: int = 5,
        filter_options: Optional[dict] = None
    ) -> pd.DataFrame:
        """
        Zoek naar de meest relevante modules voor een student.
        
        Args:
            student_input: Tekst waarin de interesses van de student staan beschreven.
            max_results: Aantal aanbevelingen dat teruggegeven moet worden.
            filter_options: Optionele filters zoals {'studycredit': 5, 'level': ['propedeuse']}.
        
        Returns:
            DataFrame met module-aanbevelingen inclusief score en uitleg.
        """
        # Valideer input
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
                'match_terms': common_terms,
                'reason': explanation_text
            })

        return pd.DataFrame(recommendations)
    
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
        """
        Haal woorden op die zowel in het studentenprofiel als de module voorkomen.
        Sorteer op relevantie volgens de modulevector en beperk tot max_terms.
        """
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

        # Vertaal indices naar woorden uit vocab
        top_words = [self.vocab[i] for i, _ in scored_words[:max_terms]]
        return top_words


    def _generate_reason(self, terms: List[str], module_name: str, similarity: float) -> str:
        """
        Genereer een tekstuele uitleg waarom de module aansluit bij het studentenprofiel.
        """
        # Bepaal beoordeling op basis van similarity
        if similarity >= 0.8:
            match_level = "excellent"
        elif similarity >= 0.6:
            match_level = "strong"
        elif similarity >= 0.4:
            match_level = "moderate"
        else:
            match_level = "weak"

        # Als er geen termen zijn, algemene verklaring
        if not terms:
            fallback = {
                "excellent": f"Deze module sluit uitstekend aan bij je algemene profiel.",
                "strong": f"Deze module past goed binnen je interesses.",
                "moderate": f"Deze module heeft raakvlakken met je profiel.",
                "weak": f"Deze module kan interessant zijn om te verkennen."
            }
            return fallback[match_level]
    
        # Format woorden lijst
        if len(terms) == 1:
            word_phrase = f"'{terms[0]}'"
        elif len(terms) == 2:
            word_phrase = f"'{terms[0]}' en '{terms[1]}'"
        else:
            word_phrase = ", ".join(terms[:-1]) + f" en {terms[-1]}"

        # Templates per match level
        templates = {
            "excellent": [
                f"Sterke match: {word_phrase} zijn kernthema's in '{module_name}'.",
                f"Perfect! '{module_name}' focust op {word_phrase}.",
                f"Top aansluiting via {word_phrase} in '{module_name}'."
            ],
            "strong": [
                f"Goede match: '{module_name}' behandelt {word_phrase}.",
                f"'{module_name}' sluit aan door focus op {word_phrase}.",
                f"Interessant: {word_phrase} komen uitgebreid terug in '{module_name}'."
            ],
            "moderate": [
                f"'{module_name}' raakt aan {word_phrase}.",
                f"Mogelijke fit: {word_phrase} zijn onderdeel van '{module_name}'.",
                f"'{module_name}' bevat elementen van {word_phrase}."
            ],
            "weak": [
                f"'{module_name}' heeft raakvlakken met {word_phrase}.",
                f"Beperkte overlap via {word_phrase} in '{module_name}'.",
                f"'{module_name}' refereert aan {word_phrase}."
            ]
        }
        
        # Kies random template (maar seed met score voor consistentie)
        random.seed(int(similarity * 1000))
        return random.choice(templates[match_level])
    
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
    return recommender.find_matches(student_profile, top_n, filters)
