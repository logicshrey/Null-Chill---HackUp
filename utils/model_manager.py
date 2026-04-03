from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from utils.config import METRICS_PATH, PRIMARY_MODEL_PATH, SECONDARY_MODEL_DIR
from utils.data_pipeline import DataPipeline


@dataclass
class PredictionResult:
    label: str
    confidence: float
    probabilities: dict[str, float]
    explanation_terms: list[dict[str, float]]


class ModelManager:
    def __init__(self, random_state: int = 42) -> None:
        self.random_state = random_state
        self.pipeline_data = None
        self.primary_pipeline: Pipeline | None = None
        self.training_metrics: dict[str, Any] = {}
        self.secondary_model = None
        self.secondary_tokenizer = None
        self.secondary_labels: list[str] = []
        self.secondary_status = "uninitialized"
        self.data_pipeline = DataPipeline(random_state=random_state)

    def ensure_models(self) -> None:
        self.load_primary_model()
        self.load_secondary_model()

    def load_primary_model(self) -> None:
        if PRIMARY_MODEL_PATH.exists():
            loaded = joblib.load(PRIMARY_MODEL_PATH)
            self.primary_pipeline = loaded["pipeline"]
            self.training_metrics = loaded.get("metrics", {})
            return
        self.train_primary_model()

    def train_primary_model(self) -> dict[str, Any]:
        dataset = self.data_pipeline.load_or_create_processed_dataset()
        train_df, test_df = train_test_split(
            dataset,
            test_size=0.2,
            random_state=self.random_state,
            stratify=dataset["label"],
        )

        pipeline = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        ngram_range=(1, 2),
                        min_df=2,
                        max_features=12000,
                        sublinear_tf=True,
                    ),
                ),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=1500,
                        class_weight="balanced",
                        multi_class="auto",
                    ),
                ),
            ]
        )
        pipeline.fit(train_df["text"], train_df["label"])

        predictions = pipeline.predict(test_df["text"])
        report = classification_report(test_df["label"], predictions, output_dict=True, zero_division=0)
        metrics = {
            "accuracy": accuracy_score(test_df["label"], predictions),
            "report": report,
            "train_size": len(train_df),
            "test_size": len(test_df),
        }

        PRIMARY_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"pipeline": pipeline, "metrics": metrics}, PRIMARY_MODEL_PATH)
        METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

        self.primary_pipeline = pipeline
        self.training_metrics = metrics
        return metrics

    def predict_primary(self, text: str) -> PredictionResult:
        self.load_primary_model()
        if self.primary_pipeline is None:
            raise RuntimeError("Primary model is unavailable.")

        probabilities_array = self.primary_pipeline.predict_proba([text])[0]
        labels = list(self.primary_pipeline.classes_)
        probabilities = {label: float(score) for label, score in zip(labels, probabilities_array)}
        best_index = int(np.argmax(probabilities_array))
        label = labels[best_index]
        confidence = float(probabilities_array[best_index])
        explanation_terms = self._top_terms_for_prediction(text, label)
        return PredictionResult(
            label=label,
            confidence=confidence,
            probabilities=probabilities,
            explanation_terms=explanation_terms,
        )

    def load_secondary_model(self) -> None:
        if self.secondary_status == "ready":
            return

        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except Exception:
            self.secondary_status = "transformers_not_installed"
            return

        label_file = SECONDARY_MODEL_DIR / "labels.json"
        if SECONDARY_MODEL_DIR.exists() and label_file.exists():
            self.secondary_tokenizer = AutoTokenizer.from_pretrained(SECONDARY_MODEL_DIR)
            self.secondary_model = AutoModelForSequenceClassification.from_pretrained(SECONDARY_MODEL_DIR)
            self.secondary_labels = json.loads(label_file.read_text(encoding="utf-8"))
            self.secondary_status = "ready"
            return

        try:
            self.train_secondary_model()
        except Exception as exc:  # pragma: no cover - depends on optional stack
            self.secondary_status = f"unavailable: {exc}"

    def train_secondary_model(self, epochs: int = 1) -> None:
        try:
            import torch
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
                Trainer,
                TrainingArguments,
            )
        except Exception as exc:  # pragma: no cover - depends on optional stack
            self.secondary_status = f"transformers_not_available: {exc}"
            return

        dataset = self.data_pipeline.load_or_create_processed_dataset()
        label_names = sorted(dataset["label"].unique().tolist())
        label_to_id = {label: idx for idx, label in enumerate(label_names)}
        id_to_label = {idx: label for label, idx in label_to_id.items()}

        train_df, eval_df = train_test_split(
            dataset,
            test_size=0.15,
            random_state=self.random_state,
            stratify=dataset["label"],
        )

        tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        model = AutoModelForSequenceClassification.from_pretrained(
            "distilbert-base-uncased",
            num_labels=len(label_names),
            id2label=id_to_label,
            label2id=label_to_id,
        )

        class ThreatDataset(torch.utils.data.Dataset):
            def __init__(self, frame: pd.DataFrame) -> None:
                encodings = tokenizer(
                    frame["text"].tolist(),
                    padding=True,
                    truncation=True,
                    max_length=128,
                )
                self.encodings = encodings
                self.labels = [label_to_id[label] for label in frame["label"].tolist()]

            def __len__(self) -> int:
                return len(self.labels)

            def __getitem__(self, index: int) -> dict[str, Any]:
                item = {key: torch.tensor(value[index]) for key, value in self.encodings.items()}
                item["labels"] = torch.tensor(self.labels[index])
                return item

        train_dataset = ThreatDataset(train_df.reset_index(drop=True))
        eval_dataset = ThreatDataset(eval_df.reset_index(drop=True))

        training_args = TrainingArguments(
            output_dir=str(SECONDARY_MODEL_DIR / "runs"),
            overwrite_output_dir=True,
            learning_rate=2e-5,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            num_train_epochs=epochs,
            logging_steps=25,
            save_strategy="no",
            evaluation_strategy="epoch",
            report_to=[],
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
        )
        trainer.train()

        SECONDARY_MODEL_DIR.mkdir(parents=True, exist_ok=True)
        trainer.save_model(SECONDARY_MODEL_DIR)
        tokenizer.save_pretrained(SECONDARY_MODEL_DIR)
        (SECONDARY_MODEL_DIR / "labels.json").write_text(json.dumps(label_names, indent=2), encoding="utf-8")

        self.secondary_model = model
        self.secondary_tokenizer = tokenizer
        self.secondary_labels = label_names
        self.secondary_status = "ready"

    def predict_secondary(self, text: str, fallback_label: str, fallback_confidence: float) -> dict[str, Any]:
        self.load_secondary_model()
        if self.secondary_status != "ready" or self.secondary_model is None or self.secondary_tokenizer is None:
            return {
                "label": fallback_label,
                "confidence": fallback_confidence,
                "status": self.secondary_status,
                "source": "fallback_primary",
            }

        import torch

        encoded = self.secondary_tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
        with torch.no_grad():
            outputs = self.secondary_model(**encoded)
            probabilities = torch.softmax(outputs.logits, dim=1).cpu().numpy()[0]

        best_index = int(np.argmax(probabilities))
        return {
            "label": self.secondary_labels[best_index],
            "confidence": float(probabilities[best_index]),
            "status": "ready",
            "source": "distilbert",
            "probabilities": {
                label: float(probabilities[idx]) for idx, label in enumerate(self.secondary_labels)
            },
        }

    def _top_terms_for_prediction(self, text: str, predicted_label: str, top_n: int = 8) -> list[dict[str, float]]:
        if self.primary_pipeline is None:
            return []

        vectorizer: TfidfVectorizer = self.primary_pipeline.named_steps["tfidf"]
        classifier: LogisticRegression = self.primary_pipeline.named_steps["clf"]

        feature_names = np.array(vectorizer.get_feature_names_out())
        transformed = vectorizer.transform([text])
        feature_indices = transformed.nonzero()[1]
        class_index = list(classifier.classes_).index(predicted_label)
        class_coefficients = classifier.coef_[class_index]

        feature_scores = []
        for feature_idx in feature_indices:
            score = transformed[0, feature_idx] * class_coefficients[feature_idx]
            feature_scores.append((feature_names[feature_idx], float(score)))

        feature_scores.sort(key=lambda item: item[1], reverse=True)
        return [{"term": term, "weight": round(weight, 4)} for term, weight in feature_scores[:top_n]]
