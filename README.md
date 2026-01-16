# KeuzeKompas AI Model

Python Flask API voor module aanbevelingen.

## Vereisten

- Python 3.9+
- pip

## Installatie

```bash
python -m venv venv

# Activate venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

## Configuratie

Check `.env` voor API settings.

## Starten

```bash
python app/main.py
```

API draait op `http://localhost:5000`

## Scripts

```bash
python app/main.py              # Start API
python -m pytest tests/         # Run tests
python -m pytest test/security/ # Security tests
```

## Afhankelijkheden

- Flask - Web framework
- scikit-learn - Machine learning
- pandas - Data processing
- numpy - Numerical computing

## Features

- Module aanbevelingen gebaseerd op student profiel
- Quiz antwoord processing
- Dataset matching algoritme
