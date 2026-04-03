# Dark Web Threat Intelligence System

AI-powered threat intelligence platform that detects credential leaks, malware sales, phishing, database dumps, and suspicious activity from dark web-style text.

## Tech Stack

- AI/ML: `spaCy (en_core_web_sm)`, `Sentence-BERT (all-MiniLM-L6-v2)`, `Scikit-learn (TF-IDF + Logistic Regression)`, `HuggingFace Transformers (DistilBERT)`, `regex`
- Backend: `FastAPI`
- Frontend: `Streamlit`
- Database: `MongoDB (pymongo)`
- Visualization: `Plotly`
- Data handling: `Pandas`, `NumPy`

## Features

- Dataset detection from `data/spam.csv` and `data/cyber.csv`
- Synthetic threat text generation when source data is missing or needs augmentation
- Structured Android malware rows converted into readable threat text
- Class balancing through oversampling
- Auto-generated `data/raw_data.csv` and `data/processed_data.csv`
- Regex-based IOC and leak pattern detection
- NER for `ORG`, `PERSON`, and `GPE`
- Semantic similarity against curated threat templates using SBERT with a safe fallback
- Primary text classifier using TF-IDF + Logistic Regression
- Secondary classifier using DistilBERT when the transformers stack is available
- Risk scoring, explainable AI output, organization tracking, and alert persistence
- FastAPI endpoints for analysis, alerts, and statistics
- Streamlit dashboard with four pages and Plotly analytics

## Project Structure

```text
project/
├── data/
│   ├── spam.csv
│   ├── cyber.csv
│   ├── raw_data.csv
│   └── processed_data.csv
├── models/
├── backend/
├── frontend/
├── utils/
├── requirements.txt
└── README.md
```

## Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Install the spaCy English model:

```bash
python -m spacy download en_core_web_sm
```

4. Make sure MongoDB is running if you want persistent storage.

## Run The Backend

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Available endpoints:

- `POST /analyze`
- `GET /alerts`
- `GET /stats`

## Run The Frontend

```bash
streamlit run frontend/app.py
```

The UI includes:

- `Analyze Text`
- `Upload Dataset`
- `Alerts Dashboard`
- `Analytics`

## Example API Request

```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"Admin login credentials for SBI with email ops@sbi.com password=Root@123\"}"
```

## Example Inputs

- `Selling Netflix combo accounts with email and password access`
- `Phishing page ready for Microsoft 365 with OTP relay`
- `Database dump available from ecommerce panel`
- `Ransomware toolkit for sale with crypter service`
- `Normal harmless discussion about patching mobile applications`

## Data Pipeline Rules

- `spam.csv` is loaded from `v1` and `v2`, then mapped to:
  - `spam -> Phishing`
  - `ham -> Normal`
- `cyber.csv` is treated as structured Android permission data.
- Malware rows are converted into descriptive text before modeling.
- Malware labels are mapped to:
  - `1 -> Malware Sale`
  - `0 -> Normal`
- Synthetic data adds realistic samples for:
  - `Credential Leak`
  - `Malware Sale`
  - `Phishing`
  - `Database Dump`
  - `Normal`

## Model Behavior

- If `data/processed_data.csv` is missing, the pipeline rebuilds it automatically.
- If the primary model is missing, it trains automatically at startup.
- If MongoDB is unavailable, the app continues without crashing and uses in-memory fallback storage.
- If optional NLP or transformers dependencies are unavailable, the system falls back safely while keeping the workflow operational.

## Notes

- The primary classifier is fully validated and saved under `models/`.
- The DistilBERT path is implemented as an optional secondary classifier and activates when the transformers stack is installed.
- Alerts include threat type, detected patterns, entities, risk level, and timestamps.
