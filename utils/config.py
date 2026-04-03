from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"

SPAM_DATA_PATH = DATA_DIR / "spam.csv"
CYBER_DATA_PATH = DATA_DIR / "cyber.csv"
RAW_DATA_PATH = DATA_DIR / "raw_data.csv"
PROCESSED_DATA_PATH = DATA_DIR / "processed_data.csv"

PRIMARY_MODEL_PATH = MODELS_DIR / "tfidf_logreg.joblib"
SECONDARY_MODEL_DIR = MODELS_DIR / "distilbert_threat"
METRICS_PATH = MODELS_DIR / "training_metrics.json"

MONGO_URI = "mongodb+srv://logicshrey_db_user:rash1516@hackupcluster.kuuvhvf.mongodb.net/?appName=HackUpCluster"
MONGO_DB_NAME = "dark_web_threat_intel"
MONGO_COLLECTION = "analyses"

LABELS = [
    "Credential Leak",
    "Malware Sale",
    "Phishing",
    "Database Dump",
    "Normal",
]

THREAT_TEMPLATES = {
    "Credential Leak": [
        "admin login credentials available for sale",
        "corporate email and password combo leaked",
        "bulk account dump with usernames and passwords",
    ],
    "Malware Sale": [
        "ransomware toolkit for sale on private forum",
        "android spyware builder with remote access panel",
        "malware loader and crypter package available",
    ],
    "Phishing": [
        "bank phishing page ready with otp bypass",
        "spoofed login portal for credential harvesting",
        "mass sms lure directing victims to fake website",
    ],
    "Database Dump": [
        "customer database dump with pii and hashes",
        "sql dump from breached ecommerce store",
        "fresh leak containing user records and card metadata",
    ],
    "Normal": [
        "general cybersecurity discussion with no threat",
        "developer forum conversation about app permissions",
        "harmless support thread with technical troubleshooting",
    ],
}
