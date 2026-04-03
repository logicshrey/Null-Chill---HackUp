from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from utils.config import LABELS, THREAT_TEMPLATES
from utils.db import MongoManager
from utils.intel_enrichment import (
    correlate_alerts,
    decode_slang,
    estimate_impact,
    extract_enriched_entities,
    normalize_multilingual_text,
    prioritize_alert,
)
from utils.model_manager import ModelManager
from utils.source_intel_service import ExternalIntelligenceService
from utils.text_utils import clean_text


REGEX_PATTERNS = {
    "emails": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "passwords": re.compile(
        r"(?i)\b(?:password|passwd|pwd|pass)\s*[:=]\s*[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\",.<>/?\\|`~]{4,}\b"
    ),
    "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "bitcoin_wallets": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    "credit_cards": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "telegram_handles": re.compile(r"(?<!\w)@[A-Za-z0-9_]{5,32}\b"),
    "onion_links": re.compile(r"\b[a-z2-7]{16,56}\.onion\b"),
    "domains": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
}

SIMULATION_TEXTS = [
    "Selling Netflix combo accounts with email:user@example.com password=Spring2026!",
    "Admin login credentials for SBI panel and database dump available on hidden forum",
    "Phishing page ready for Microsoft 365 users with Telegram support @op_vendor",
    "Ransomware toolkit for sale with crypter and loader access",
    "Normal harmless discussion on secure app permissions and developer updates",
]


class ThreatIntelligenceEngine:
    def __init__(self) -> None:
        self.model_manager = ModelManager()
        self.db = MongoManager()
        self._nlp = None
        self._semantic_model = None
        self._template_embeddings = None
        self._semantic_fallback = None

    def bootstrap(self) -> None:
        self.model_manager.ensure_models()

    def analyze_text(self, text: str, persist: bool = True) -> dict[str, Any]:
        original_text = str(text or "").strip()
        self.bootstrap()

        regex_matches = self.detect_patterns(original_text)
        multilingual_analysis = normalize_multilingual_text(original_text)
        slang_decoder = decode_slang(multilingual_analysis["normalized_text"])
        analysis_text = clean_text(slang_decoder["normalized_text"])

        entities = self.extract_entities(original_text)
        enriched_entities = extract_enriched_entities(original_text, regex_matches)
        all_entities = self._merge_entities(entities, enriched_entities)

        semantic_matches = self.semantic_similarity(analysis_text)
        primary_prediction = self.model_manager.predict_primary(analysis_text)
        secondary_prediction = self.model_manager.predict_secondary(
            analysis_text,
            fallback_label=primary_prediction.label,
            fallback_confidence=primary_prediction.confidence,
        )

        threat_type = self.resolve_threat_type(primary_prediction.label, semantic_matches)
        confidence = max(
            primary_prediction.confidence,
            secondary_prediction.get("confidence", 0.0),
            semantic_matches.get("top_score", 0.0),
        )
        risk_level = self.compute_risk_level(regex_matches, all_entities, threat_type)
        impact_assessment = estimate_impact(
            threat_type=threat_type,
            text=original_text,
            regex_matches=regex_matches,
            entities=all_entities,
            slang=slang_decoder,
        )

        result = {
            "input_text": original_text,
            "cleaned_text": analysis_text,
            "threat_type": threat_type,
            "risk_level": risk_level,
            "confidence_score": round(float(confidence), 4),
            "patterns": regex_matches,
            "entities": all_entities,
            "enriched_entities": enriched_entities,
            "multilingual_analysis": multilingual_analysis,
            "slang_decoder": slang_decoder,
            "semantic_analysis": semantic_matches,
            "primary_classification": {
                "label": primary_prediction.label,
                "confidence": round(primary_prediction.confidence, 4),
                "probabilities": {label: round(score, 4) for label, score in primary_prediction.probabilities.items()},
                "explanation_terms": primary_prediction.explanation_terms,
            },
            "secondary_classification": secondary_prediction,
            "explanation": self.build_explanation(
                threat_type=threat_type,
                risk_level=risk_level,
                regex_matches=regex_matches,
                entities=all_entities,
                primary_prediction=primary_prediction,
                semantic_matches=semantic_matches,
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        recent_alerts = self.db.fetch_alerts(limit=200)
        correlation = correlate_alerts(result, recent_alerts)
        alert_priority = prioritize_alert(
            risk_level=risk_level,
            confidence_score=float(confidence),
            impact_assessment=impact_assessment,
            correlation=correlation,
        )
        result["correlation"] = correlation
        result["impact_assessment"] = impact_assessment
        result["alert_priority"] = alert_priority

        alert = {
            "text": original_text,
            "results": result,
            "alerts": {
                "threat_type": threat_type,
                "entities": all_entities,
                "patterns": regex_matches,
                "risk_level": risk_level,
                "priority": alert_priority["priority"],
                "timestamp": result["timestamp"],
            },
            "timestamps": {
                "analyzed_at": result["timestamp"],
            },
        }

        storage_status = self.db.insert_analysis(alert) if persist else {"stored": False, "warning": None}
        result["storage"] = storage_status
        if self.db.warning:
            result["warning"] = self.db.warning
        return result

    def collect_external_intelligence(self, query: str, persist: bool = True, demo: bool = False) -> dict[str, Any]:
        """Collect public-source intelligence and normalize it into the existing alert schema."""
        self.bootstrap()
        service = ExternalIntelligenceService()
        collection = service.build_demo_collection(query) if demo else service.collect(query)
        recent_alerts = self.db.fetch_alerts(limit=200)
        findings: list[dict[str, Any]] = []

        for finding in collection.get("findings", []):
            result = self._build_external_finding_result(
                query=query,
                finding=finding,
                platforms=collection.get("platforms", []),
                recent_alerts=recent_alerts,
            )
            storage_status = self._persist_result_alert(result, persist=persist)
            result["storage"] = storage_status
            if self.db.warning:
                result["warning"] = self.db.warning
            findings.append(result)
            recent_alerts.append({"results": result})

        return {
            "organization": collection.get("organization", query),
            "platforms": collection.get("platforms", []),
            "findings": findings,
            "warnings": collection.get("warnings", []),
            "generated_at": collection.get("generated_at"),
            "demo_mode": bool(collection.get("demo_mode", demo)),
            "stored_findings": sum(1 for finding in findings if finding.get("storage", {}).get("stored")),
            "count": len(findings),
        }

    def detect_patterns(self, text: str) -> dict[str, list[str]]:
        matches: dict[str, list[str]] = {}
        for pattern_name, pattern in REGEX_PATTERNS.items():
            unique_matches = list(dict.fromkeys(pattern.findall(text)))
            matches[pattern_name] = unique_matches
        return matches

    def extract_entities(self, text: str) -> list[dict[str, str]]:
        nlp = self._load_spacy()
        if nlp is None:
            return []

        doc = nlp(text)
        entities = []
        for ent in doc.ents:
            if ent.label_ in {"ORG", "PERSON", "GPE"}:
                entities.append({"text": ent.text, "label": ent.label_})
        return entities

    def semantic_similarity(self, text: str) -> dict[str, Any]:
        templates = []
        labels = []
        for label, label_templates in THREAT_TEMPLATES.items():
            for template in label_templates:
                templates.append(template)
                labels.append(label)

        if not text:
            return {"top_label": "Normal", "top_score": 0.0, "label_scores": {}, "matches": []}

        model = self._load_sentence_transformer()
        if model is not None:
            if self._template_embeddings is None:
                self._template_embeddings = model.encode(templates)
            query_embedding = model.encode([text])[0]
            similarities = self._cosine_similarity_vector(query_embedding, self._template_embeddings)
        else:
            if self._semantic_fallback is None:
                vectorizer = TfidfVectorizer(ngram_range=(1, 2))
                matrix = vectorizer.fit_transform(templates)
                self._semantic_fallback = (vectorizer, matrix)
            vectorizer, matrix = self._semantic_fallback
            query_embedding = vectorizer.transform([text])
            similarities = (matrix @ query_embedding.T).toarray().ravel()

        label_scores: dict[str, float] = {label: 0.0 for label in LABELS}
        detailed_matches = []
        for template, label, similarity in zip(templates, labels, similarities):
            similarity = float(similarity)
            label_scores[label] = max(label_scores.get(label, 0.0), similarity)
            detailed_matches.append(
                {
                    "label": label,
                    "template": template,
                    "score": round(similarity, 4),
                }
            )

        detailed_matches.sort(key=lambda item: item["score"], reverse=True)
        top_match = detailed_matches[0] if detailed_matches else {"label": "Normal", "score": 0.0}
        return {
            "top_label": top_match["label"],
            "top_score": round(top_match["score"], 4),
            "label_scores": {label: round(score, 4) for label, score in label_scores.items()},
            "matches": detailed_matches[:5],
            "model": "sbert" if model is not None else "tfidf_fallback",
        }

    def compute_risk_level(
        self,
        regex_matches: dict[str, list[str]],
        entities: list[dict[str, str]],
        threat_type: str,
    ) -> str:
        email_hits = bool(regex_matches.get("emails"))
        password_hits = bool(regex_matches.get("passwords"))
        org_hits = any(entity["label"] == "ORG" for entity in entities)
        high_signal_matches = sum(bool(values) for values in regex_matches.values())

        if email_hits and password_hits:
            return "HIGH"
        if threat_type in {"Credential Leak", "Database Dump", "Malware Sale"} and high_signal_matches >= 2:
            return "HIGH"
        if org_hits or threat_type in {"Phishing", "Credential Leak", "Malware Sale", "Database Dump"}:
            return "MEDIUM"
        return "LOW"

    def _merge_entities(self, base_entities: list[dict[str, str]], extra_entities: list[dict[str, str]]) -> list[dict[str, str]]:
        merged = []
        seen = set()
        for entity in [*base_entities, *extra_entities]:
            key = (entity.get("text", "").lower(), entity.get("label"))
            if key not in seen and entity.get("text"):
                seen.add(key)
                merged.append(entity)
        return merged

    def resolve_threat_type(self, primary_label: str, semantic_matches: dict[str, Any]) -> str:
        semantic_label = semantic_matches.get("top_label", primary_label)
        semantic_score = semantic_matches.get("top_score", 0.0)
        if primary_label == "Normal" and semantic_score >= 0.55 and semantic_label != "Normal":
            return semantic_label
        return primary_label

    def build_explanation(
        self,
        threat_type: str,
        risk_level: str,
        regex_matches: dict[str, list[str]],
        entities: list[dict[str, str]],
        primary_prediction: Any,
        semantic_matches: dict[str, Any],
    ) -> list[str]:
        explanations = [
            f"Primary classifier predicted {primary_prediction.label} with {primary_prediction.confidence:.2%} confidence.",
            f"Semantic matcher aligned most closely with {semantic_matches.get('top_label', 'Normal')} at score {semantic_matches.get('top_score', 0.0):.2f}.",
            f"Final threat type is {threat_type} with {risk_level} risk.",
        ]
        if regex_matches.get("emails"):
            explanations.append("Regex detected exposed email addresses.")
        if regex_matches.get("passwords"):
            explanations.append("Regex detected password-like content paired with credential signals.")
        orgs = [entity["text"] for entity in entities if entity["label"] == "ORG"]
        if orgs:
            explanations.append(f"Organization tracking identified: {', '.join(orgs[:5])}.")
        return explanations

    def _build_external_finding_result(
        self,
        query: str,
        finding: dict[str, Any],
        platforms: list[str],
        recent_alerts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        # The external collectors hand the engine a normalized text bundle so the same
        # NLP, regex, correlation, and prioritization layers can run unchanged.
        original_text = str(finding.get("text", "") or "").strip()
        regex_matches = self.detect_patterns(original_text)
        regex_matches["usernames"] = list(finding.get("usernames", []))
        regex_matches["platforms"] = [finding.get("source", "Unknown")]

        multilingual_analysis = normalize_multilingual_text(original_text)
        slang_decoder = decode_slang(multilingual_analysis["normalized_text"])
        analysis_text = clean_text(slang_decoder["normalized_text"])

        entities = self.extract_entities(original_text)
        enriched_entities = extract_enriched_entities(original_text, regex_matches)
        external_entities = [
            {"text": finding.get("organization", query), "label": "ORG"},
            *({"text": email, "label": "EMAIL"} for email in finding.get("emails", [])),
            *({"text": username, "label": "USERNAME"} for username in finding.get("usernames", [])),
            {"text": finding.get("source", "Unknown"), "label": "PLATFORM"},
        ]
        all_entities = self._merge_entities(entities, [*enriched_entities, *external_entities])

        semantic_matches = self.semantic_similarity(analysis_text)
        primary_prediction = self.model_manager.predict_primary(analysis_text)
        secondary_prediction = self.model_manager.predict_secondary(
            analysis_text,
            fallback_label=primary_prediction.label,
            fallback_confidence=primary_prediction.confidence,
        )

        threat_type = str(finding.get("type") or self.resolve_threat_type(primary_prediction.label, semantic_matches))
        confidence = max(
            0.7,
            primary_prediction.confidence,
            secondary_prediction.get("confidence", 0.0),
            semantic_matches.get("top_score", 0.0),
        )
        risk_score = round(float(finding.get("risk_score", 0.0)), 2)
        risk_level = self._map_risk_score_to_level(risk_score)
        impact_assessment = estimate_impact(
            threat_type=threat_type,
            text=original_text,
            regex_matches=regex_matches,
            entities=all_entities,
            slang=slang_decoder,
        )
        impact_assessment["source"] = finding.get("source")
        impact_assessment["volume"] = int(finding.get("volume", 0))

        result = {
            "input_text": original_text,
            "cleaned_text": analysis_text,
            "threat_type": threat_type,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "source": finding.get("source"),
            "platforms": list(platforms or [finding.get("source")]),
            "demo_mode": any(item.get("metadata", {}).get("demo") for item in finding.get("raw_items", [])),
            "confidence_score": round(float(confidence), 4),
            "patterns": regex_matches,
            "entities": all_entities,
            "enriched_entities": enriched_entities,
            "multilingual_analysis": multilingual_analysis,
            "slang_decoder": slang_decoder,
            "semantic_analysis": semantic_matches,
            "primary_classification": {
                "label": primary_prediction.label,
                "confidence": round(primary_prediction.confidence, 4),
                "probabilities": {label: round(score, 4) for label, score in primary_prediction.probabilities.items()},
                "explanation_terms": primary_prediction.explanation_terms,
            },
            "secondary_classification": secondary_prediction,
            "timestamp": f"{finding.get('date_found')}T00:00:00+00:00",
            "external_intelligence": {
                "organization": finding.get("organization", query),
                "platforms": list(platforms or [finding.get("source")]),
                "emails": list(finding.get("emails", [])),
                "usernames": list(finding.get("usernames", [])),
                "type": threat_type,
                "risk_score": risk_score,
                "source": finding.get("source"),
                "date_found": finding.get("date_found"),
                "volume": int(finding.get("volume", 0)),
                "demo_mode": any(item.get("metadata", {}).get("demo") for item in finding.get("raw_items", [])),
                "raw_items": list(finding.get("raw_items", [])),
            },
        }

        result["explanation"] = [
            *self.build_explanation(
                threat_type=threat_type,
                risk_level=risk_level,
                regex_matches=regex_matches,
                entities=all_entities,
                primary_prediction=primary_prediction,
                semantic_matches=semantic_matches,
            ),
            f"External intelligence source {finding.get('source', 'Unknown')} matched query {query}.",
            f"Risk score {risk_score:.2f} was derived from platform reputation, exposed data type, and finding volume.",
        ]
        if result["demo_mode"]:
            result["explanation"].append("Demo mode generated this synthetic finding for safe UI validation.")

        correlation = correlate_alerts(result, recent_alerts)
        alert_priority = prioritize_alert(
            risk_level=risk_level,
            confidence_score=float(confidence),
            impact_assessment=impact_assessment,
            correlation=correlation,
        )
        result["correlation"] = correlation
        result["impact_assessment"] = impact_assessment
        result["alert_priority"] = alert_priority
        return result

    def simulate_alerts(self, count: int = 5) -> list[dict[str, Any]]:
        results = []
        for index in range(max(1, count)):
            text = SIMULATION_TEXTS[index % len(SIMULATION_TEXTS)]
            results.append(self.analyze_text(text, persist=True))
        return results

    def get_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.db.fetch_alerts(limit=limit)

    def get_stats(self) -> dict[str, Any]:
        self.bootstrap()
        stats = self.db.get_stats()
        stats["model_metrics"] = self.model_manager.training_metrics
        stats["secondary_status"] = self.model_manager.secondary_status
        return stats

    def _load_spacy(self):
        if self._nlp is not None:
            return self._nlp

        try:
            import spacy

            try:
                self._nlp = spacy.load("en_core_web_sm")
            except OSError:
                from spacy.cli import download

                download("en_core_web_sm")
                self._nlp = spacy.load("en_core_web_sm")
            return self._nlp
        except Exception:
            self._nlp = None
            return None

    def _load_sentence_transformer(self):
        if self._semantic_model is not None:
            return self._semantic_model

        try:
            from sentence_transformers import SentenceTransformer

            self._semantic_model = SentenceTransformer("all-MiniLM-L6-v2")
            return self._semantic_model
        except Exception:
            self._semantic_model = None
            return None

    def _cosine_similarity_vector(self, query_embedding: np.ndarray, template_embeddings: np.ndarray) -> np.ndarray:
        query_norm = np.linalg.norm(query_embedding)
        template_norms = np.linalg.norm(template_embeddings, axis=1)
        denominator = np.maximum(query_norm * template_norms, 1e-12)
        return np.dot(template_embeddings, query_embedding) / denominator

    @staticmethod
    def _map_risk_score_to_level(risk_score: float) -> str:
        if risk_score >= 0.75:
            return "HIGH"
        if risk_score >= 0.45:
            return "MEDIUM"
        return "LOW"

    def _persist_result_alert(self, result: dict[str, Any], persist: bool = True) -> dict[str, Any]:
        alert = {
            "text": result.get("input_text", ""),
            "source": result.get("source"),
            "results": result,
            "alerts": {
                "threat_type": result.get("threat_type"),
                "entities": result.get("entities", []),
                "patterns": result.get("patterns", {}),
                "risk_level": result.get("risk_level"),
                "risk_score": result.get("risk_score"),
                "priority": result.get("alert_priority", {}).get("priority"),
                "timestamp": result.get("timestamp"),
                "source": result.get("source"),
            },
            "timestamps": {
                "analyzed_at": result.get("timestamp"),
            },
        }
        return self.db.insert_analysis(alert) if persist else {"stored": False, "warning": None}
