from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable

import pandas as pd

from utils.config import (
    CYBER_DATA_PATH,
    LABELS,
    PROCESSED_DATA_PATH,
    RAW_DATA_PATH,
    SPAM_DATA_PATH,
)
from utils.text_utils import clean_text, humanize_feature_name


SENSITIVE_PERMISSION_HINTS = {
    "camera": "camera access",
    "sms": "sms messaging",
    "send sms": "outbound sms",
    "read sms": "sms inbox access",
    "record audio": "microphone recording",
    "read contacts": "contact harvesting",
    "read phone state": "device identifiers",
    "get deviceid": "device id collection",
    "get line1number": "phone number collection",
    "get simserialnumber": "sim serial collection",
    "get last location": "location tracking",
    "access fine location": "precise location",
    "access coarse location": "coarse location",
    "internet": "network communication",
    "system alert window": "overlay control",
    "write settings": "settings modification",
    "request install packages": "package sideloading",
    "receive boot completed": "persistence on boot",
    "read logs": "log inspection",
    "exec": "command execution",
    "loadclass": "dynamic code loading",
    "dofinal": "cryptographic execution",
    "openconnection": "remote server contact",
}


@dataclass
class DatasetSummary:
    rows: int
    class_distribution: dict[str, int]
    sources: dict[str, int]


class DataPipeline:
    def __init__(self, random_state: int = 42) -> None:
        self.random_state = random_state
        self.random = random.Random(random_state)

    def load_spam_dataset(self) -> pd.DataFrame:
        if not SPAM_DATA_PATH.exists():
            return pd.DataFrame(columns=["text", "label", "source"])

        df = pd.read_csv(SPAM_DATA_PATH, encoding="latin-1")
        df = df.rename(columns={"v1": "label", "v2": "text"})
        df = df[["text", "label"]].copy()
        df["label"] = df["label"].map({"spam": "Phishing", "ham": "Normal"}).fillna("Normal")
        df["source"] = "sms"
        return df

    def load_malware_dataset(self) -> pd.DataFrame:
        if not CYBER_DATA_PATH.exists():
            return pd.DataFrame(columns=["text", "label", "source"])

        df = pd.read_csv(CYBER_DATA_PATH)
        label_column = self._find_label_column(df.columns)
        feature_columns = [column for column in df.columns if column != label_column]
        converted_rows = []

        for _, row in df.iterrows():
            raw_label = row[label_column]
            normalized_label = self._normalize_malware_label(raw_label)
            converted_rows.append(
                {
                    "text": self._malware_row_to_text(row, feature_columns, normalized_label),
                    "label": "Malware Sale" if normalized_label == 1 else "Normal",
                    "source": "malware",
                }
            )

        malware_df = pd.DataFrame(converted_rows)
        return self.balance_dataset(malware_df)

    def generate_synthetic_dataset(self, size: int = 700) -> pd.DataFrame:
        size = max(500, min(1000, size))
        orgs = ["sbi", "paypal", "microsoft", "amazon", "bank of america", "netflix", "coinbase"]
        markets = ["hidden market", "private channel", "trusted vendor board", "invite only forum"]
        labels = [
            "Credential Leak",
            "Malware Sale",
            "Phishing",
            "Database Dump",
            "Normal",
        ]

        templates = {
            "Credential Leak": [
                "selling {org} combo accounts with verified email and password access",
                "fresh admin login credentials for {org} portal available in {market}",
                "premium rdp and mailbox credentials with password reset method included",
                "corporate vpn access bundle with usernames passwords and recovery email",
            ],
            "Malware Sale": [
                "ransomware toolkit for sale with builder panel and persistence module",
                "android banking trojan source package and crypter service offered",
                "stealer logs plus loader service available through {market}",
                "botnet panel access with malware deployment support and tutorial",
            ],
            "Phishing": [
                "phishing page ready for {org} with otp relay and sms lure templates",
                "sms campaign kit impersonating {org} customer support for credential capture",
                "spoofed payment portal clone hosted on private server with redirect chain",
                "telegram operator offering live phishing infrastructure and target lists",
            ],
            "Database Dump": [
                "database dump available from {org} including emails phone numbers and hashes",
                "fresh sql archive from breached ecommerce panel posted in {market}",
                "customer dump with pii addresses and partial payment records for resale",
                "large leak containing staff records api keys and internal user tables",
            ],
            "Normal": [
                "normal harmless discussion about software updates and account recovery tips",
                "developer forum thread reviewing application permissions and ux feedback",
                "cybersecurity study notes covering phishing awareness for students",
                "routine chat about patch management and secure deployment practices",
            ],
        }

        synthetic_rows: list[dict[str, str]] = []
        per_label = size // len(labels)

        for label in labels:
            for _ in range(per_label):
                text = self.random.choice(templates[label]).format(
                    org=self.random.choice(orgs),
                    market=self.random.choice(markets),
                )
                synthetic_rows.append({"text": text, "label": label, "source": "synthetic"})

        while len(synthetic_rows) < size:
            label = self.random.choice(labels)
            text = self.random.choice(templates[label]).format(
                org=self.random.choice(orgs),
                market=self.random.choice(markets),
            )
            synthetic_rows.append({"text": text, "label": label, "source": "synthetic"})

        return pd.DataFrame(synthetic_rows)

    def standardize_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        standardized = df.copy()
        standardized["text"] = standardized["text"].astype(str).map(clean_text)
        standardized["label"] = standardized["label"].astype(str).str.strip()
        standardized = standardized[standardized["text"].str.len() > 0].reset_index(drop=True)
        return standardized

    def balance_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return df

        grouped = df.groupby("label")
        max_count = grouped.size().max()
        balanced_parts = []

        for label, group in grouped:
            replace = len(group) < max_count
            sampled = group.sample(
                n=max_count,
                replace=replace,
                random_state=self.random_state,
            )
            balanced_parts.append(sampled)

        balanced = pd.concat(balanced_parts, ignore_index=True)
        return balanced.sample(frac=1.0, random_state=self.random_state).reset_index(drop=True)

    def build_datasets(self, synthetic_size: int = 700) -> tuple[pd.DataFrame, pd.DataFrame, DatasetSummary]:
        datasets = [
            self.load_spam_dataset(),
            self.load_malware_dataset(),
            self.generate_synthetic_dataset(synthetic_size),
        ]
        available = [dataset for dataset in datasets if not dataset.empty]
        raw_df = pd.concat(available, ignore_index=True) if available else self.generate_synthetic_dataset(synthetic_size)
        raw_df = raw_df[["text", "label", "source"]].sample(frac=1.0, random_state=self.random_state).reset_index(drop=True)

        processed_df = self.standardize_dataset(raw_df)
        processed_df = self.balance_dataset(processed_df)
        processed_df = processed_df.sample(frac=1.0, random_state=self.random_state).reset_index(drop=True)

        RAW_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        raw_df.to_csv(RAW_DATA_PATH, index=False)
        processed_df.to_csv(PROCESSED_DATA_PATH, index=False)

        summary = DatasetSummary(
            rows=len(processed_df),
            class_distribution=processed_df["label"].value_counts().to_dict(),
            sources=raw_df["source"].value_counts().to_dict(),
        )
        return raw_df, processed_df, summary

    def load_or_create_processed_dataset(self) -> pd.DataFrame:
        if PROCESSED_DATA_PATH.exists():
            df = pd.read_csv(PROCESSED_DATA_PATH)
            if {"text", "label"}.issubset(df.columns):
                return df
        _, processed_df, _ = self.build_datasets()
        return processed_df

    def _find_label_column(self, columns: Iterable[str]) -> str:
        for column in columns:
            if str(column).strip().lower() == "label":
                return column
        return list(columns)[-1]

    def _normalize_malware_label(self, value: object) -> int:
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "malware", "true", "yes"}:
                return 1
            return 0
        return int(bool(value))

    def _malware_row_to_text(self, row: pd.Series, feature_columns: list[str], normalized_label: int) -> str:
        active_features = []
        for column in feature_columns:
            try:
                value = float(row[column])
            except (TypeError, ValueError):
                continue
            if value >= 1:
                active_features.append(humanize_feature_name(column))

        suspicious = self._summarize_permissions(active_features)
        benign = [
            feature
            for feature in active_features
            if feature in {"internet", "access network state", "access wifi state", "vibrate"}
        ]

        if normalized_label == 1:
            sentences = [
                "suspicious android app requesting multiple sensitive permissions",
            ]
            if suspicious:
                sentences.append(f"app requests {', '.join(suspicious[:6])}")
            if len(active_features) > 8:
                sentences.append("behavior suggests persistence, credential access, or data exfiltration")
            if any("sms" in feature for feature in active_features):
                sentences.append("app can interact with sms channels and may support phishing or otp theft")
            if any("camera" in feature or "audio" in feature for feature in active_features):
                sentences.append("device surveillance capabilities are present")
            return ". ".join(sentences)

        sentences = ["standard android application with limited sensitive activity"]
        if benign:
            sentences.append(f"common permissions include {', '.join(benign[:4])}")
        elif active_features:
            sentences.append(f"permissions include {', '.join(active_features[:4])}")
        return ". ".join(sentences)

    def _summarize_permissions(self, active_features: list[str]) -> list[str]:
        summarized = []
        for feature in active_features:
            matched = False
            for key, replacement in SENSITIVE_PERMISSION_HINTS.items():
                if key in feature:
                    summarized.append(replacement)
                    matched = True
                    break
            if not matched and any(token in feature for token in ("read", "write", "send", "receive", "camera", "audio", "location")):
                summarized.append(feature)
        seen = []
        for item in summarized:
            if item not in seen:
                seen.append(item)
        return seen
