import os
from pathlib import Path

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"

SPAM_DATA_PATH = DATA_DIR / "spam.csv"
CYBER_DATA_PATH = DATA_DIR / "cyber.csv"
RAW_DATA_PATH = DATA_DIR / "raw_data.csv"
PROCESSED_DATA_PATH = DATA_DIR / "processed_data.csv"

PRIMARY_MODEL_PATH = MODELS_DIR / "tfidf_logreg.joblib"
SECONDARY_MODEL_DIR = MODELS_DIR / "distilbert_threat"
METRICS_PATH = MODELS_DIR / "training_metrics.json"
MONITORING_STATE_PATH = DATA_DIR / "monitoring_state.json"

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "dark_web_threat_intel")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "analyses")
MONGO_ENABLED = os.getenv("MONGO_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8001") or 8001)
WATCHLIST_DEFAULT_INTERVAL_SECONDS = int(os.getenv("WATCHLIST_DEFAULT_INTERVAL_SECONDS", "300") or 300)
WATCHLIST_MIN_INTERVAL_SECONDS = int(os.getenv("WATCHLIST_MIN_INTERVAL_SECONDS", "60") or 60)
WEBHOOK_TIMEOUT_SECONDS = float(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "10") or 10)

# External intelligence providers are configured through environment variables so
# operational secrets stay out of the codebase while the integration remains plug-and-play.
TELEGRAM_API_ID = int(os.getenv("TELEGRAM_API_ID", "0") or 0)
TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "")
TELEGRAM_SESSION_STRING = os.getenv("TELEGRAM_SESSION_STRING", "")

PASTEBIN_API_KEY = os.getenv("PASTEBIN_API_KEY", "")

DEHASHED_EMAIL = os.getenv("DEHASHED_EMAIL", "")
DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
INTELX_API_BASE = os.getenv("INTELX_API_BASE", "https://free.intelx.io")
LEAKIX_API_KEY = os.getenv("LEAKIX_API_KEY", "")

PUBLIC_INTEL_MAX_ITEMS = int(os.getenv("PUBLIC_INTEL_MAX_ITEMS", "10") or 10)
PUBLIC_INTEL_REQUEST_TIMEOUT = float(os.getenv("PUBLIC_INTEL_REQUEST_TIMEOUT", "12") or 12)

PLATFORM_REPUTATION_SCORES = {
    "Telegram": 0.72,
    "Pastebin": 0.58,
    "Dehashed": 0.9,
    "GitHub": 0.61,
    "IntelX": 0.79,
    "LeakIX": 0.76,
}

DATA_SENSITIVITY_SCORES = {
    "credentials": 0.95,
    "email addresses": 0.7,
    "usernames": 0.55,
    "hashed passwords": 0.88,
    "phone numbers": 0.62,
    "ip addresses": 0.58,
    "undetermined": 0.35,
}

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
