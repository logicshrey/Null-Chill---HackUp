from __future__ import annotations

from collections import Counter
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
        case_updates: list[dict[str, Any]] = []

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
            if persist:
                case_record, action = self.db.save_case(
                    self._build_exposure_case(
                        query=query,
                        result=result,
                        watchlist=None,
                    )
                )
                case_updates.append(
                    {
                        "action": action,
                        "case_id": case_record.get("id"),
                        "title": case_record.get("title"),
                        "priority": case_record.get("priority"),
                    }
                )

        summary = self._build_external_collection_summary(
            query=query,
            findings=findings,
            collection=collection,
        )
        return {
            "organization": collection.get("organization", query),
            "platforms": collection.get("platforms", []),
            "findings": findings,
            "summary": summary,
            "warnings": collection.get("warnings", []),
            "generated_at": collection.get("generated_at"),
            "demo_mode": bool(collection.get("demo_mode", demo)),
            "stored_findings": sum(1 for finding in findings if finding.get("storage", {}).get("stored")),
            "case_updates": case_updates,
            "count": len(findings),
        }

    def sync_watchlist(self, watchlist: dict[str, Any]) -> dict[str, Any]:
        query = str(watchlist.get("query", "")).strip()
        demo_mode = bool(watchlist.get("demo_mode", False))
        response = self.collect_external_intelligence(query, persist=False, demo=demo_mode)
        updates: list[dict[str, Any]] = []

        for result in response.get("findings", []):
            case_record, action = self.db.save_case(
                self._build_exposure_case(
                    query=query,
                    result=result,
                    watchlist=watchlist,
                )
            )
            updates.append({"action": action, "case": case_record})

        self.db.record_audit_event(
            {
                "event_type": "watchlist_sync",
                "watchlist_id": watchlist.get("id"),
                "watchlist_name": watchlist.get("name"),
                "query": query,
                "case_count": len(updates),
            }
        )
        return {
            "watchlist": watchlist,
            "collection": response,
            "updates": updates,
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
                "data_types": list(finding.get("data_types", [])),
                "data_breakdown": list(finding.get("data_breakdown", [])),
                "type": threat_type,
                "risk_score": risk_score,
                "source": finding.get("source"),
                "date_found": finding.get("date_found"),
                "volume": int(finding.get("volume", 0)),
                "estimated_record_count": finding.get("estimated_record_count"),
                "estimated_records": finding.get("estimated_records"),
                "affected_assets": list(finding.get("affected_assets", [])),
                "matched_indicators": list(finding.get("matched_indicators", [])),
                "source_locations": list(finding.get("source_locations", [])),
                "summary": finding.get("summary"),
                "related_sources": [],
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
        if finding.get("estimated_records"):
            result["explanation"].append(f"Estimated exposure size: {finding.get('estimated_records')}.")
        if finding.get("source_locations"):
            result["explanation"].append(
                f"Observed on: {', '.join(list(finding.get('source_locations', []))[:3])}."
            )
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

    def _build_external_collection_summary(
        self,
        query: str,
        findings: list[dict[str, Any]],
        collection: dict[str, Any],
    ) -> dict[str, Any]:
        platforms = list(collection.get("platforms", []))
        demo_mode = bool(collection.get("demo_mode", False))
        generated_at = collection.get("generated_at")

        if not findings:
            return {
                "organization": collection.get("organization", query),
                "platforms": platforms,
                "source_count": 0,
                "total_findings": 0,
                "total_evidence_items": 0,
                "estimated_total_records": None,
                "estimated_total_records_label": "No leak volume identified",
                "combined_priority": {
                    "priority": "LOW",
                    "priority_score": 0,
                    "rationale": ["No source findings were strong enough to build a correlated leak summary."],
                },
                "data_type_breakdown": [],
                "affected_assets": [],
                "recurring_indicators": [],
                "cross_source_relations": [],
                "source_breakdown": [],
                "generated_at": generated_at,
                "demo_mode": demo_mode,
            }

        data_type_counter: Counter[str] = Counter()
        asset_counter: Counter[str] = Counter()
        indicator_counter: Counter[str] = Counter()
        source_breakdown: list[dict[str, Any]] = []
        total_evidence_items = 0
        total_records = 0
        has_numeric_total = False

        for result in findings:
            external = result.get("external_intelligence", {})
            data_breakdown = list(external.get("data_breakdown", []))
            for entry in data_breakdown:
                label = str(entry.get("label", "undetermined"))
                count = int(entry.get("count", 0) or 0)
                data_type_counter[label] += max(1, count) if label != "undetermined" else 0

            affected_assets = list(external.get("affected_assets", []))
            matched_indicators = list(external.get("matched_indicators", []))
            for asset in affected_assets:
                asset_counter[str(asset)] += 1
            for indicator in matched_indicators:
                indicator_counter[str(indicator)] += 1

            estimated_record_count = external.get("estimated_record_count")
            if isinstance(estimated_record_count, int):
                has_numeric_total = True
                total_records += estimated_record_count

            total_evidence_items += int(external.get("volume", 0) or 0)
            source_breakdown.append(
                {
                    "source": external.get("source") or result.get("source"),
                    "threat_type": result.get("threat_type"),
                    "priority": result.get("alert_priority", {}).get("priority", "LOW"),
                    "priority_score": int(result.get("alert_priority", {}).get("priority_score", 0) or 0),
                    "risk_level": result.get("risk_level", "LOW"),
                    "risk_score": float(result.get("risk_score", 0.0) or 0.0),
                    "confidence_score": float(result.get("confidence_score", 0.0) or 0.0),
                    "estimated_record_count": estimated_record_count if isinstance(estimated_record_count, int) else None,
                    "estimated_records": external.get("estimated_records") or "Amount not disclosed by the source",
                    "data_types": list(external.get("data_types", [])),
                    "data_breakdown": data_breakdown,
                    "affected_assets": affected_assets,
                    "matched_indicators": matched_indicators,
                    "source_locations": list(external.get("source_locations", [])),
                    "summary": external.get("summary") or result.get("impact_assessment", {}).get("summary"),
                    "timestamp": result.get("timestamp"),
                    "evidence_count": int(external.get("volume", 0) or 0),
                    "correlation_score": int(result.get("correlation", {}).get("campaign_score", 0) or 0),
                    "_indicator_keys": {str(item).strip().lower() for item in matched_indicators if str(item).strip()},
                    "_asset_keys": {str(item).strip().lower() for item in affected_assets if str(item).strip()},
                    "_data_type_keys": {str(item).strip().lower() for item in external.get("data_types", []) if str(item).strip()},
                }
            )

        cross_source_relations = self._build_cross_source_relations(source_breakdown)
        relation_map: dict[str, list[dict[str, Any]]] = {}
        for relation in cross_source_relations:
            left, right = relation["sources"]
            relation_map.setdefault(left, []).append(
                {
                    "source": right,
                    "strength_score": relation["strength_score"],
                    "summary": relation["summary"],
                    "shared_indicators": relation["shared_indicators"],
                    "shared_assets": relation["shared_assets"],
                }
            )
            relation_map.setdefault(right, []).append(
                {
                    "source": left,
                    "strength_score": relation["strength_score"],
                    "summary": relation["summary"],
                    "shared_indicators": relation["shared_indicators"],
                    "shared_assets": relation["shared_assets"],
                }
            )

        for result in findings:
            external = result.get("external_intelligence", {})
            source_name = str(external.get("source") or result.get("source") or "")
            external["related_sources"] = relation_map.get(source_name, [])[:4]

        priority_scores = [entry["priority_score"] for entry in source_breakdown]
        max_priority = max(priority_scores) if priority_scores else 0
        avg_priority = sum(priority_scores) / len(priority_scores) if priority_scores else 0
        source_bonus = min(12, max(0, len(source_breakdown) - 1) * 4)
        relation_bonus = min(
            18,
            (len(cross_source_relations[:3]) * 4)
            + max((relation["strength_score"] for relation in cross_source_relations), default=0) // 20,
        )
        exposure_bonus = 0
        if has_numeric_total:
            if total_records >= 10000:
                exposure_bonus = 12
            elif total_records >= 1000:
                exposure_bonus = 9
            elif total_records >= 100:
                exposure_bonus = 6
            elif total_records >= 10:
                exposure_bonus = 3
        else:
            exposure_bonus = min(8, len(indicator_counter))

        combined_priority_score = min(
            100,
            int(round((max_priority * 0.5) + (avg_priority * 0.2) + source_bonus + relation_bonus + exposure_bonus)),
        )
        combined_priority = {
            "priority": self._priority_from_score(combined_priority_score),
            "priority_score": combined_priority_score,
            "rationale": [
                f"Strongest source finding contributed {max_priority} priority points.",
                f"Average source priority contributed {int(round(avg_priority * 0.2))} blended points.",
                f"Cross-source corroboration contributed {relation_bonus} points across {len(cross_source_relations)} linked relation(s).",
                f"Exposure scale contributed {exposure_bonus} points.",
            ],
        }

        total_records_label = "No leak volume identified"
        if has_numeric_total:
            total_records_label = f"Approximately {total_records:,} records across all sources"
        elif indicator_counter:
            total_records_label = f"At least {len(indicator_counter):,} exposed indicator(s) observed across all sources"
        elif total_evidence_items:
            total_records_label = f"{total_evidence_items:,} evidence item(s) observed across all sources"

        sanitized_breakdown = []
        for entry in source_breakdown:
            sanitized_breakdown.append(
                {
                    key: value
                    for key, value in entry.items()
                    if not key.startswith("_")
                }
            )

        return {
            "organization": collection.get("organization", query),
            "platforms": platforms,
            "source_count": len(source_breakdown),
            "total_findings": len(findings),
            "total_evidence_items": total_evidence_items,
            "estimated_total_records": total_records if has_numeric_total else None,
            "estimated_total_records_label": total_records_label,
            "combined_priority": combined_priority,
            "data_type_breakdown": [
                {"label": label, "count": count}
                for label, count in data_type_counter.most_common(8)
            ],
            "affected_assets": [asset for asset, _ in asset_counter.most_common(10)],
            "recurring_indicators": [indicator for indicator, _ in indicator_counter.most_common(12)],
            "cross_source_relations": cross_source_relations[:6],
            "source_breakdown": sanitized_breakdown,
            "generated_at": generated_at,
            "demo_mode": demo_mode,
        }

    def _build_cross_source_relations(self, source_breakdown: list[dict[str, Any]]) -> list[dict[str, Any]]:
        relations: list[dict[str, Any]] = []
        for index, left in enumerate(source_breakdown):
            for right in source_breakdown[index + 1 :]:
                shared_indicators = sorted(left["_indicator_keys"].intersection(right["_indicator_keys"]))[:6]
                shared_assets = sorted(left["_asset_keys"].intersection(right["_asset_keys"]))[:4]
                shared_data_types = sorted(left["_data_type_keys"].intersection(right["_data_type_keys"]))[:4]
                same_threat_type = left["threat_type"] == right["threat_type"]

                strength_score = (
                    len(shared_indicators) * 18
                    + len(shared_assets) * 12
                    + len(shared_data_types) * 6
                    + (10 if same_threat_type else 0)
                )
                if strength_score < 12:
                    continue

                relation_reasons = []
                if shared_indicators:
                    relation_reasons.append("shared exposed indicators")
                if shared_assets:
                    relation_reasons.append("same affected assets")
                if shared_data_types:
                    relation_reasons.append("matching leak data types")
                if same_threat_type:
                    relation_reasons.append(f"same threat type ({left['threat_type']})")

                relations.append(
                    {
                        "sources": [left["source"], right["source"]],
                        "strength_score": min(100, strength_score),
                        "shared_indicators": shared_indicators,
                        "shared_assets": shared_assets,
                        "shared_data_types": shared_data_types,
                        "summary": "Linked through " + ", ".join(relation_reasons) + ".",
                    }
                )

        relations.sort(key=lambda item: item["strength_score"], reverse=True)
        return relations

    @staticmethod
    def _priority_from_score(priority_score: int) -> str:
        if priority_score >= 85:
            return "CRITICAL"
        if priority_score >= 65:
            return "HIGH"
        if priority_score >= 40:
            return "MEDIUM"
        return "LOW"

    def _build_exposure_case(
        self,
        query: str,
        result: dict[str, Any],
        watchlist: dict[str, Any] | None,
    ) -> dict[str, Any]:
        external = result.get("external_intelligence", {})
        source_name = str(external.get("source") or result.get("source") or "Unknown")
        organization = str(external.get("organization") or query)
        matched_indicators = list(external.get("matched_indicators", []))
        affected_assets = list(external.get("affected_assets", []))
        exposed_data_types = list(external.get("data_types", []))
        recommended_actions = self._recommended_actions_for_case(
            threat_type=result.get("threat_type", "Unknown"),
            affected_assets=affected_assets,
            exposed_data_types=exposed_data_types,
        )
        confidence_basis = [
            f"Priority score {result.get('alert_priority', {}).get('priority_score', 0)} from risk, impact, and correlation scoring.",
            f"Source {source_name} reported {external.get('estimated_records') or 'an undisclosed amount of'} exposure.",
            *list(result.get("explanation", []))[:3],
        ]
        source_locations = list(external.get("source_locations", []))
        summary = external.get("summary") or result.get("impact_assessment", {}).get("summary") or "Exposure detected."
        fingerprint_parts = [
            organization.lower(),
            str(result.get("threat_type", "")).lower(),
            "|".join(sorted(item.lower() for item in affected_assets[:4])),
            "|".join(sorted(item.lower() for item in matched_indicators[:4])),
        ]
        fingerprint_key = "::".join(fingerprint_parts)
        case_title = f"{organization} exposure detected via {source_name}"
        event_timestamp = result.get("timestamp")
        first_seen = event_timestamp

        evidence_id = f"{source_name.lower()}::{event_timestamp}::{fingerprint_key}"
        source_entry = {
            "source": source_name,
            "first_seen": first_seen,
            "last_seen": event_timestamp,
            "evidence_count": int(external.get("volume", 0) or 0),
            "source_locations": source_locations,
            "risk_score": float(result.get("risk_score", 0.0) or 0.0),
            "confidence_score": float(result.get("confidence_score", 0.0) or 0.0),
            "related_sources": list(external.get("related_sources", [])),
        }

        business_unit = str(
            (watchlist or {}).get("business_unit")
            or self._infer_business_unit(affected_assets, exposed_data_types)
        )

        case_payload = {
            "fingerprint_key": fingerprint_key,
            "organization": organization,
            "query": query,
            "title": case_title,
            "summary": summary,
            "executive_summary": self._build_executive_case_summary(result, external),
            "case_status": "new",
            "owner": str((watchlist or {}).get("owner") or "Unassigned"),
            "business_unit": business_unit,
            "priority": result.get("alert_priority", {}).get("priority", "LOW"),
            "priority_score": int(result.get("alert_priority", {}).get("priority_score", 0) or 0),
            "risk_level": result.get("risk_level", "LOW"),
            "confidence_score": float(result.get("confidence_score", 0.0) or 0.0),
            "threat_type": result.get("threat_type"),
            "severity_reason": self._severity_reason_for_case(result, external),
            "affected_assets": affected_assets,
            "matched_indicators": matched_indicators,
            "exposed_data_types": exposed_data_types,
            "estimated_total_records": external.get("estimated_record_count"),
            "estimated_total_records_label": external.get("estimated_records") or "Amount not disclosed by the source",
            "recommended_actions": recommended_actions,
            "confidence_basis": confidence_basis,
            "watchlists": [str((watchlist or {}).get("name") or organization)],
            "sources": [source_entry],
            "evidence": [
                {
                    "evidence_id": evidence_id,
                    "timestamp": event_timestamp,
                    "source": source_name,
                    "summary": summary,
                    "source_locations": source_locations,
                    "matched_indicators": matched_indicators,
                    "data_breakdown": list(external.get("data_breakdown", [])),
                    "raw_excerpt": str(result.get("input_text", "") or "")[:800],
                    "provenance": {
                        "query": query,
                        "demo_mode": bool(external.get("demo_mode", False)),
                        "raw_items": list(external.get("raw_items", []))[:5],
                    },
                }
            ],
            "timeline": [
                {
                    "timestamp": event_timestamp,
                    "event_type": "detected",
                    "message": f"{source_name} produced a new exposure signal for {organization}.",
                }
            ],
            "first_seen": first_seen,
            "last_seen": event_timestamp,
        }
        return case_payload

    @staticmethod
    def _recommended_actions_for_case(
        threat_type: str,
        affected_assets: list[str],
        exposed_data_types: list[str],
    ) -> list[str]:
        actions = [
            "Validate the exposed asset and verify whether the data belongs to your organization.",
            "Preserve source evidence and notify the incident response owner.",
        ]
        if "credentials" in exposed_data_types or threat_type == "Credential Leak":
            actions.append("Reset exposed credentials, revoke active sessions, and review MFA coverage.")
        if "email addresses" in exposed_data_types:
            actions.append("Notify exposed users and monitor for phishing or account takeover activity.")
        if "ip addresses" in exposed_data_types or any(asset.count(".") >= 1 for asset in affected_assets):
            actions.append("Inspect affected infrastructure for internet exposure, weak services, and misconfigurations.")
        if threat_type == "Database Dump":
            actions.append("Determine whether regulated customer or employee records are involved and begin disclosure assessment.")
        return actions

    @staticmethod
    def _severity_reason_for_case(result: dict[str, Any], external: dict[str, Any]) -> str:
        asset_count = len(external.get("affected_assets", []))
        source_count = 1 + len(external.get("related_sources", []))
        exposure = external.get("estimated_records") or "an unknown amount of data"
        return (
            f"{result.get('threat_type', 'Exposure')} with {result.get('risk_level', 'LOW')} risk, "
            f"{exposure}, {asset_count} affected asset(s), and corroboration across {source_count} source(s)."
        )

    @staticmethod
    def _infer_business_unit(affected_assets: list[str], exposed_data_types: list[str]) -> str:
        asset_blob = " ".join(affected_assets).lower()
        if any(keyword in asset_blob for keyword in ("vpn", "admin", "rdp", "ssh", "api", "prod")):
            return "Infrastructure Security"
        if "email addresses" in exposed_data_types or "credentials" in exposed_data_types:
            return "Identity & Access"
        if "bulk personal records" in exposed_data_types:
            return "Privacy & Compliance"
        return "Security Operations"

    @staticmethod
    def _build_executive_case_summary(result: dict[str, Any], external: dict[str, Any]) -> str:
        return (
            f"{external.get('source', 'A monitored source')} exposed {external.get('estimated_records') or 'an unknown amount of data'} "
            f"linked to {external.get('organization', 'the organization')}. Priority is "
            f"{result.get('alert_priority', {}).get('priority', 'LOW')} due to {result.get('threat_type', 'detected exposure').lower()} "
            f"signals and the affected assets {', '.join(external.get('affected_assets', [])[:3]) or 'still being identified'}."
        )

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
