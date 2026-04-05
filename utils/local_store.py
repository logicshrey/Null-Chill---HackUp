from __future__ import annotations

import json
import threading
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _dedupe_strings(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(normalized)
    return results


class LocalMonitoringStore:
    """Durable fallback storage for alerts, cases, watchlists, and audit events."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._state = self._load()

    def _default_state(self) -> dict[str, Any]:
        return {
            "alerts": [],
            "cases": [],
            "watchlists": [],
            "audit_events": [],
            "scheduler": {
                "last_tick_at": None,
                "last_cycle_summary": None,
            },
        }

    def _load(self) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            state = self._default_state()
            self.path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            return state
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            state = self._default_state()
            self.path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            return state

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:12]}"

    def insert_alert(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            record = dict(payload)
            record.setdefault("id", self._new_id("alert"))
            record.setdefault("created_at", _now_iso())
            self._state["alerts"].append(record)
            self._state["alerts"] = self._state["alerts"][-2000:]
            self._save()
            return {"stored": True, "id": record["id"], "warning": "Stored in local fallback state."}

    def fetch_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._state["alerts"][-limit:][::-1])

    def list_cases(
        self,
        *,
        limit: int = 200,
        status: str | None = None,
        priority: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            cases = list(self._state["cases"])

        if status:
            cases = [case for case in cases if str(case.get("case_status", "")).lower() == status.lower()]
        if priority:
            cases = [case for case in cases if str(case.get("priority", "")).lower() == priority.lower()]
        if search:
            needle = search.lower()
            filtered: list[dict[str, Any]] = []
            for case in cases:
                haystack = " ".join(
                    [
                        str(case.get("title", "")),
                        str(case.get("summary", "")),
                        " ".join(case.get("affected_assets", [])),
                        " ".join(case.get("matched_indicators", [])),
                        " ".join(source.get("source", "") for source in case.get("sources", [])),
                    ]
                ).lower()
                if needle in haystack:
                    filtered.append(case)
            cases = filtered

        cases.sort(key=lambda case: case.get("last_seen", ""), reverse=True)
        return cases[:limit]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._lock:
            for case in self._state["cases"]:
                if case.get("id") == case_id:
                    return dict(case)
        return None

    def save_case(self, candidate: dict[str, Any]) -> tuple[dict[str, Any], str]:
        with self._lock:
            match_index = self._find_matching_case(candidate)
            now_iso = _now_iso()

            if match_index is None:
                case = dict(candidate)
                case["id"] = self._new_id("case")
                case.setdefault("created_at", now_iso)
                case.setdefault("first_seen", candidate.get("last_seen", now_iso))
                case.setdefault("last_seen", now_iso)
                case.setdefault("timeline", [])
                case.setdefault("watchlists", [])
                case.setdefault("sources", [])
                case.setdefault("evidence", [])
                case.setdefault("recommended_actions", [])
                case.setdefault("confidence_basis", [])
                case["source_count"] = len(case.get("sources", []))
                case["evidence_count"] = len(case.get("evidence", []))
                case["corroborating_source_count"] = max(0, case["source_count"] - 1)
                self._state["cases"].append(case)
                self._save()
                return dict(case), "created"

            existing = self._state["cases"][match_index]
            existing["summary"] = candidate.get("summary", existing.get("summary"))
            existing["executive_summary"] = candidate.get("executive_summary", existing.get("executive_summary"))
            existing["priority_score"] = max(int(existing.get("priority_score", 0)), int(candidate.get("priority_score", 0)))
            existing["priority"] = candidate.get("priority") if int(candidate.get("priority_score", 0)) >= int(existing.get("priority_score", 0)) else existing.get("priority")
            existing["risk_level"] = candidate.get("risk_level", existing.get("risk_level"))
            existing["severity_reason"] = candidate.get("severity_reason", existing.get("severity_reason"))
            existing["business_unit"] = candidate.get("business_unit", existing.get("business_unit"))
            existing["owner"] = existing.get("owner") or candidate.get("owner") or "Unassigned"
            existing["last_seen"] = max(existing.get("last_seen", ""), candidate.get("last_seen", ""))
            existing["first_seen"] = min(
                value for value in [existing.get("first_seen"), candidate.get("first_seen")] if isinstance(value, str) and value
            )
            existing["affected_assets"] = _dedupe_strings([*existing.get("affected_assets", []), *candidate.get("affected_assets", [])])
            existing["matched_indicators"] = _dedupe_strings([*existing.get("matched_indicators", []), *candidate.get("matched_indicators", [])])
            existing["exposed_data_types"] = _dedupe_strings([*existing.get("exposed_data_types", []), *candidate.get("exposed_data_types", [])])
            existing["watchlists"] = _dedupe_strings([*existing.get("watchlists", []), *candidate.get("watchlists", [])])
            existing["recommended_actions"] = _dedupe_strings(
                [*existing.get("recommended_actions", []), *candidate.get("recommended_actions", [])]
            )
            existing["confidence_basis"] = _dedupe_strings(
                [*existing.get("confidence_basis", []), *candidate.get("confidence_basis", [])]
            )
            existing["evidence"] = self._merge_evidence(existing.get("evidence", []), candidate.get("evidence", []))
            existing["sources"] = self._merge_sources(existing.get("sources", []), candidate.get("sources", []))
            existing["timeline"] = self._merge_timeline(existing.get("timeline", []), candidate.get("timeline", []))
            existing["estimated_total_records"] = self._max_optional_int(
                existing.get("estimated_total_records"), candidate.get("estimated_total_records")
            )
            existing["estimated_total_records_label"] = candidate.get(
                "estimated_total_records_label", existing.get("estimated_total_records_label")
            )
            existing["source_count"] = len(existing.get("sources", []))
            existing["evidence_count"] = len(existing.get("evidence", []))
            existing["corroborating_source_count"] = max(0, existing["source_count"] - 1)
            existing["updated_at"] = now_iso
            self._save()
            return dict(existing), "updated"

    def update_case(self, case_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            for case in self._state["cases"]:
                if case.get("id") != case_id:
                    continue
                for key in ("case_status", "owner", "business_unit"):
                    if key in updates and updates[key] is not None:
                        case[key] = updates[key]
                if updates.get("comment"):
                    case.setdefault("timeline", []).append(
                        {
                            "timestamp": _now_iso(),
                            "event_type": "comment",
                            "message": str(updates["comment"]),
                        }
                    )
                case["updated_at"] = _now_iso()
                self._save()
                return dict(case)
        return None

    def list_watchlists(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            watchlists = list(self._state["watchlists"])
        if enabled_only:
            watchlists = [watchlist for watchlist in watchlists if watchlist.get("enabled", True)]
        watchlists.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        return watchlists

    def save_watchlist(self, payload: dict[str, Any], watchlist_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            now_iso = _now_iso()
            record = {
                "name": payload.get("name"),
                "query": payload.get("query"),
                "enabled": bool(payload.get("enabled", True)),
                "interval_seconds": int(payload.get("interval_seconds", 300)),
                "owner": payload.get("owner") or "Threat Intel Team",
                "business_unit": payload.get("business_unit") or "Security Operations",
                "description": payload.get("description") or "",
                "webhook_url": payload.get("webhook_url") or "",
                "demo_mode": bool(payload.get("demo_mode", False)),
                "tags": _dedupe_strings(payload.get("tags", [])),
                "assets": _dedupe_strings(payload.get("assets", [])),
                "last_run_at": payload.get("last_run_at"),
                "next_run_at": payload.get("next_run_at"),
                "last_error": payload.get("last_error"),
                "last_success_at": payload.get("last_success_at"),
                "last_duration_ms": payload.get("last_duration_ms", 0),
                "last_case_count": payload.get("last_case_count", 0),
            }

            if watchlist_id is None:
                record["id"] = self._new_id("watch")
                record["created_at"] = now_iso
                record["updated_at"] = now_iso
                self._state["watchlists"].append(record)
            else:
                for index, existing in enumerate(self._state["watchlists"]):
                    if existing.get("id") != watchlist_id:
                        continue
                    merged = dict(existing)
                    merged.update(record)
                    merged["updated_at"] = now_iso
                    self._state["watchlists"][index] = merged
                    self._save()
                    return merged
                record["id"] = watchlist_id
                record["created_at"] = now_iso
                record["updated_at"] = now_iso
                self._state["watchlists"].append(record)

            self._save()
            return dict(self._state["watchlists"][-1])

    def delete_watchlist(self, watchlist_id: str) -> bool:
        with self._lock:
            initial_length = len(self._state["watchlists"])
            self._state["watchlists"] = [item for item in self._state["watchlists"] if item.get("id") != watchlist_id]
            changed = len(self._state["watchlists"]) != initial_length
            if changed:
                self._save()
            return changed

    def record_watchlist_run(
        self,
        watchlist_id: str,
        *,
        duration_ms: int,
        case_count: int,
        error: str | None = None,
    ) -> dict[str, Any] | None:
        with self._lock:
            now_iso = _now_iso()
            for watchlist in self._state["watchlists"]:
                if watchlist.get("id") != watchlist_id:
                    continue
                watchlist["last_run_at"] = now_iso
                watchlist["last_duration_ms"] = duration_ms
                watchlist["last_case_count"] = case_count
                watchlist["last_error"] = error
                watchlist["next_run_at"] = (
                    datetime.now(timezone.utc) + timedelta(seconds=max(30, int(watchlist.get("interval_seconds", 300))))
                ).isoformat()
                if error is None:
                    watchlist["last_success_at"] = now_iso
                self._save()
                return dict(watchlist)
        return None

    def update_scheduler_state(self, summary: dict[str, Any]) -> None:
        with self._lock:
            self._state["scheduler"]["last_tick_at"] = _now_iso()
            self._state["scheduler"]["last_cycle_summary"] = summary
            self._save()

    def record_audit_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            event = dict(payload)
            event.setdefault("id", self._new_id("audit"))
            event.setdefault("timestamp", _now_iso())
            self._state["audit_events"].append(event)
            self._state["audit_events"] = self._state["audit_events"][-500:]
            self._save()
            return event

    def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._state["audit_events"][-limit:][::-1])

    def export_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "generated_at": _now_iso(),
                "cases": list(self._state["cases"]),
                "watchlists": list(self._state["watchlists"]),
                "audit_events": list(self._state["audit_events"][-100:]),
                "scheduler": dict(self._state["scheduler"]),
            }

    def get_case_stats(self) -> dict[str, Any]:
        with self._lock:
            cases = list(self._state["cases"])
            watchlists = list(self._state["watchlists"])
            scheduler = dict(self._state["scheduler"])

        priority_counter = Counter()
        status_counter = Counter()
        source_counter = Counter()
        asset_counter = Counter()
        data_counter = Counter()
        business_units = Counter()
        open_review_durations: list[float] = []
        timeline_counter: Counter[str] = Counter()
        critical_cases = 0
        corroborated_cases = 0
        new_cases_24h = 0
        now = datetime.now(timezone.utc)

        for case in cases:
            priority_counter[case.get("priority", "LOW")] += 1
            status_counter[case.get("case_status", "new")] += 1
            if int(case.get("priority_score", 0)) >= 85:
                critical_cases += 1
            if int(case.get("corroborating_source_count", 0)) > 0:
                corroborated_cases += 1
            first_seen = _parse_iso(case.get("first_seen"))
            last_seen = _parse_iso(case.get("last_seen"))
            if first_seen and (now - first_seen) <= timedelta(hours=24):
                new_cases_24h += 1
            if last_seen:
                timeline_counter[last_seen.date().isoformat()] += 1
            if case.get("case_status") != "closed" and first_seen:
                open_review_durations.append((now - first_seen).total_seconds() / 3600)
            for source in case.get("sources", []):
                source_counter[source.get("source", "Unknown")] += 1
            for asset in case.get("affected_assets", []):
                asset_counter[asset] += 1
            for data_type in case.get("exposed_data_types", []):
                data_counter[data_type] += 1
            business_units[case.get("business_unit", "Security Operations")] += 1

        timeline = []
        for days_back in range(6, -1, -1):
            day = (now - timedelta(days=days_back)).date().isoformat()
            timeline.append({"bucket": day, "cases": timeline_counter.get(day, 0)})

        watchlist_health = []
        for watchlist in watchlists:
            watchlist_health.append(
                {
                    "id": watchlist.get("id"),
                    "name": watchlist.get("name"),
                    "enabled": watchlist.get("enabled", True),
                    "last_run_at": watchlist.get("last_run_at"),
                    "last_success_at": watchlist.get("last_success_at"),
                    "last_duration_ms": int(watchlist.get("last_duration_ms", 0) or 0),
                    "last_case_count": int(watchlist.get("last_case_count", 0) or 0),
                    "last_error": watchlist.get("last_error"),
                }
            )

        return {
            "case_count": len(cases),
            "active_cases": sum(1 for case in cases if case.get("case_status") not in {"closed", "resolved"}),
            "critical_cases": critical_cases,
            "corroborated_cases": corroborated_cases,
            "watchlist_count": len(watchlists),
            "enabled_watchlists": sum(1 for item in watchlists if item.get("enabled", True)),
            "new_cases_24h": new_cases_24h,
            "priority_distribution": dict(priority_counter),
            "status_distribution": dict(status_counter),
            "source_distribution": dict(source_counter),
            "asset_distribution": dict(asset_counter.most_common(10)),
            "exposure_distribution": dict(data_counter.most_common(10)),
            "business_unit_distribution": dict(business_units),
            "timeline": timeline,
            "watchlist_health": watchlist_health,
            "mean_time_to_review_hours": round(sum(open_review_durations) / len(open_review_durations), 2)
            if open_review_durations
            else 0,
            "scheduler": scheduler,
        }

    def _find_matching_case(self, candidate: dict[str, Any]) -> int | None:
        for index, case in enumerate(self._state["cases"]):
            if case.get("fingerprint_key") and case.get("fingerprint_key") == candidate.get("fingerprint_key"):
                return index

            if case.get("organization", "").lower() != str(candidate.get("organization", "")).lower():
                continue
            if case.get("threat_type") != candidate.get("threat_type"):
                continue

            shared_assets = set(case.get("affected_assets", [])).intersection(candidate.get("affected_assets", []))
            shared_indicators = set(case.get("matched_indicators", [])).intersection(candidate.get("matched_indicators", []))
            if shared_assets or shared_indicators:
                return index

        return None

    @staticmethod
    def _merge_evidence(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = {item.get("evidence_id") for item in existing}
        merged = list(existing)
        for item in incoming:
            if item.get("evidence_id") in seen:
                continue
            seen.add(item.get("evidence_id"))
            merged.append(item)
        merged.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return merged[:100]

    @staticmethod
    def _merge_sources(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {item.get("source", ""): dict(item) for item in existing}
        for item in incoming:
            key = item.get("source", "")
            if key not in merged:
                merged[key] = dict(item)
                continue
            current = merged[key]
            current["evidence_count"] = int(current.get("evidence_count", 0)) + int(item.get("evidence_count", 0))
            current["first_seen"] = min(current.get("first_seen", ""), item.get("first_seen", ""))
            current["last_seen"] = max(current.get("last_seen", ""), item.get("last_seen", ""))
            current["source_locations"] = _dedupe_strings(
                [*current.get("source_locations", []), *item.get("source_locations", [])]
            )
            current["related_sources"] = item.get("related_sources", current.get("related_sources", []))
        return list(merged.values())

    @staticmethod
    def _merge_timeline(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged = list(existing)
        existing_keys = {(item.get("timestamp"), item.get("event_type"), item.get("message")) for item in existing}
        for item in incoming:
            key = (item.get("timestamp"), item.get("event_type"), item.get("message"))
            if key in existing_keys:
                continue
            existing_keys.add(key)
            merged.append(item)
        merged.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return merged[:60]

    @staticmethod
    def _max_optional_int(left: Any, right: Any) -> int | None:
        candidates = [value for value in (left, right) if isinstance(value, int)]
        return max(candidates) if candidates else None
