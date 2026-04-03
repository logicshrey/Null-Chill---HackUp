from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from utils.config import MONGO_COLLECTION, MONGO_DB_NAME, MONGO_URI


class MongoManager:
    def __init__(self, mongo_uri: str = MONGO_URI) -> None:
        self.mongo_uri = mongo_uri
        self.connected = False
        self.warning: str | None = None
        self.client = None
        self.collection = None
        self.fallback_alerts: list[dict[str, Any]] = []
        self._connect()

    def _connect(self) -> None:
        try:
            from pymongo import MongoClient

            self.client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=1500)
            self.client.admin.command("ping")
            self.collection = self.client[MONGO_DB_NAME][MONGO_COLLECTION]
            self.connected = True
            self.warning = None
        except Exception as exc:
            self.connected = False
            self.collection = None
            self.warning = f"MongoDB unavailable: {exc}"

    def insert_analysis(self, payload: dict[str, Any]) -> dict[str, Any]:
        record = dict(payload)
        record.setdefault("created_at", datetime.now(timezone.utc).isoformat())

        if self.connected and self.collection is not None:
            try:
                inserted = self.collection.insert_one(record)
                return {"stored": True, "id": str(inserted.inserted_id), "warning": None}
            except Exception as exc:
                self.warning = f"MongoDB write failed: {exc}"

        self.fallback_alerts.append(record)
        self.fallback_alerts = self.fallback_alerts[-500:]
        return {"stored": False, "id": None, "warning": self.warning}

    def fetch_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        if self.connected and self.collection is not None:
            try:
                records = list(self.collection.find().sort("created_at", -1).limit(limit))
                for record in records:
                    record["_id"] = str(record["_id"])
                return records
            except Exception as exc:
                self.warning = f"MongoDB read failed: {exc}"

        return list(reversed(self.fallback_alerts[-limit:]))

    def get_stats(self) -> dict[str, Any]:
        alerts = self.fetch_alerts(limit=500)
        threat_counter = Counter()
        risk_counter = Counter()
        entity_counter = Counter()
        org_counter = Counter()
        priority_counter = Counter()
        language_counter = Counter()
        data_type_counter = Counter()
        domain_counter = Counter()
        source_counter = Counter()
        correlated_alerts = 0
        campaign_scores: list[int] = []
        impact_scores: list[int] = []

        for alert in alerts:
            result = alert.get("results", alert)
            threat_counter[result.get("threat_type", "Unknown")] += 1
            risk_counter[result.get("risk_level", "Unknown")] += 1
            priority_counter[result.get("alert_priority", {}).get("priority", "Unknown")] += 1
            language_counter[result.get("multilingual_analysis", {}).get("language", "english_or_unknown")] += 1
            if result.get("correlation", {}).get("correlated_alerts_count", 0) > 0:
                correlated_alerts += 1
            if result.get("correlation", {}).get("campaign_score") is not None:
                campaign_scores.append(int(result["correlation"]["campaign_score"]))
            if result.get("impact_assessment", {}).get("impact_score") is not None:
                impact_scores.append(int(result["impact_assessment"]["impact_score"]))
            source_name = result.get("source") or result.get("external_intelligence", {}).get("source")
            if source_name:
                source_counter[source_name] += 1
            for exposed_type in result.get("impact_assessment", {}).get("exposed_data_types", []):
                data_type_counter[exposed_type] += 1
            for entity in result.get("entities", []):
                entity_counter[entity.get("text", "").lower()] += 1
                if entity.get("label") == "ORG":
                    org_counter[entity.get("text", "").lower()] += 1
            for entity in result.get("enriched_entities", []):
                if entity.get("label") == "DOMAIN":
                    domain_counter[entity.get("text", "").lower()] += 1

        return {
            "total_alerts": len(alerts),
            "threat_distribution": dict(threat_counter),
            "risk_levels": dict(risk_counter),
            "priority_distribution": dict(priority_counter),
            "language_distribution": dict(language_counter),
            "data_exposure_distribution": dict(data_type_counter),
            "source_distribution": dict(source_counter),
            "entity_frequency": dict(entity_counter.most_common(20)),
            "organization_tracking": dict(org_counter.most_common(20)),
            "domain_frequency": dict(domain_counter.most_common(20)),
            "correlation_overview": {
                "correlated_alerts": correlated_alerts,
                "average_campaign_score": round(sum(campaign_scores) / len(campaign_scores), 2) if campaign_scores else 0,
                "average_impact_score": round(sum(impact_scores) / len(impact_scores), 2) if impact_scores else 0,
            },
            "mongo_connected": self.connected,
            "warning": self.warning,
        }
