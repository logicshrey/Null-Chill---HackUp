from __future__ import annotations

import json
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests

from utils.config import WATCHLIST_MIN_INTERVAL_SECONDS, WEBHOOK_TIMEOUT_SECONDS


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


class MonitoringEventBus:
    def __init__(self) -> None:
        self._subscribers: set[queue.Queue[str]] = set()
        self._lock = threading.Lock()
        self._history: list[str] = []

    def publish(self, payload: dict[str, Any]) -> None:
        message = json.dumps({"sent_at": _now_iso(), **payload})
        with self._lock:
            self._history.append(message)
            self._history = self._history[-50:]
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            subscriber.put(message)

    def subscribe(self) -> queue.Queue[str]:
        subscriber: queue.Queue[str] = queue.Queue()
        with self._lock:
            self._subscribers.add(subscriber)
            history = list(self._history[-10:])
        for message in history:
            subscriber.put(message)
        return subscriber

    def unsubscribe(self, subscriber: queue.Queue[str]) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)


class MonitoringScheduler:
    def __init__(self, engine: Any, event_bus: MonitoringEventBus) -> None:
        self.engine = engine
        self.event_bus = event_bus
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run_loop, name="watchlist-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def _run_loop(self) -> None:
        while not self._stop_event.wait(5):
            watchlists = self.engine.db.list_watchlists(enabled_only=True)
            cycle_summary = {
                "watchlists_considered": len(watchlists),
                "watchlists_executed": 0,
                "cases_touched": 0,
                "last_tick_at": _now_iso(),
            }
            now = datetime.now(timezone.utc)

            for watchlist in watchlists:
                next_run_at = _parse_iso(watchlist.get("next_run_at"))
                if next_run_at and next_run_at > now:
                    continue
                outcome = self.run_watchlist(watchlist, trigger="scheduled")
                cycle_summary["watchlists_executed"] += 1
                cycle_summary["cases_touched"] += outcome.get("case_count", 0)

            self.engine.db.update_scheduler_state(cycle_summary)

    def run_watchlist_now(self, watchlist_id: str) -> dict[str, Any]:
        for watchlist in self.engine.db.list_watchlists(enabled_only=False):
            if watchlist.get("id") == watchlist_id:
                return self.run_watchlist(watchlist, trigger="manual")
        raise KeyError(f"Unknown watchlist: {watchlist_id}")

    def run_watchlist(self, watchlist: dict[str, Any], *, trigger: str) -> dict[str, Any]:
        started_at = time.perf_counter()
        error_message: str | None = None
        updates: list[dict[str, Any]] = []
        collection_summary: dict[str, Any] | None = None

        try:
            response = self.engine.sync_watchlist(watchlist)
            updates = response.get("updates", [])
            collection_summary = response.get("collection", {}).get("summary", {})
            self._emit_case_events(watchlist, updates, trigger=trigger)
            self._dispatch_webhook_if_configured(watchlist, updates, collection_summary)
        except Exception as exc:
            error_message = str(exc)
            self.event_bus.publish(
                {
                    "event_type": "watchlist_error",
                    "watchlist_id": watchlist.get("id"),
                    "watchlist_name": watchlist.get("name"),
                    "message": error_message,
                }
            )
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        self.engine.db.record_watchlist_run(
            watchlist.get("id"),
            duration_ms=duration_ms,
            case_count=len(updates),
            error=error_message,
        )
        return {
            "watchlist_id": watchlist.get("id"),
            "watchlist_name": watchlist.get("name"),
            "case_count": len(updates),
            "duration_ms": duration_ms,
            "error": error_message,
            "summary": collection_summary,
        }

    def _emit_case_events(self, watchlist: dict[str, Any], updates: list[dict[str, Any]], *, trigger: str) -> None:
        for update in updates:
            case = update.get("case", {})
            self.event_bus.publish(
                {
                    "event_type": "case_updated",
                    "action": update.get("action"),
                    "trigger": trigger,
                    "watchlist_id": watchlist.get("id"),
                    "watchlist_name": watchlist.get("name"),
                    "case": {
                        "id": case.get("id"),
                        "title": case.get("title"),
                        "priority": case.get("priority"),
                        "priority_score": case.get("priority_score"),
                        "case_status": case.get("case_status"),
                        "last_seen": case.get("last_seen"),
                    },
                }
            )

    def _dispatch_webhook_if_configured(
        self,
        watchlist: dict[str, Any],
        updates: list[dict[str, Any]],
        collection_summary: dict[str, Any] | None,
    ) -> None:
        webhook_url = str(watchlist.get("webhook_url") or "").strip()
        if not webhook_url or not updates:
            return

        payload = {
            "watchlist": {
                "id": watchlist.get("id"),
                "name": watchlist.get("name"),
                "query": watchlist.get("query"),
            },
            "summary": collection_summary or {},
            "cases": [
                {
                    "id": update.get("case", {}).get("id"),
                    "title": update.get("case", {}).get("title"),
                    "priority": update.get("case", {}).get("priority"),
                    "priority_score": update.get("case", {}).get("priority_score"),
                    "summary": update.get("case", {}).get("summary"),
                }
                for update in updates
            ],
        }

        try:
            requests.post(webhook_url, json=payload, timeout=WEBHOOK_TIMEOUT_SECONDS)
            self.engine.db.record_audit_event(
                {
                    "event_type": "webhook_delivery",
                    "watchlist_id": watchlist.get("id"),
                    "watchlist_name": watchlist.get("name"),
                    "target": webhook_url,
                    "result": "success",
                    "case_count": len(updates),
                }
            )
        except Exception as exc:
            self.engine.db.record_audit_event(
                {
                    "event_type": "webhook_delivery",
                    "watchlist_id": watchlist.get("id"),
                    "watchlist_name": watchlist.get("name"),
                    "target": webhook_url,
                    "result": "failed",
                    "error": str(exc),
                    "case_count": len(updates),
                }
            )

    @staticmethod
    def normalize_watchlist_payload(payload: dict[str, Any]) -> dict[str, Any]:
        interval_seconds = max(
            WATCHLIST_MIN_INTERVAL_SECONDS,
            int(payload.get("interval_seconds", WATCHLIST_MIN_INTERVAL_SECONDS)),
        )
        return {
            "name": str(payload.get("name", "")).strip(),
            "query": str(payload.get("query", "")).strip(),
            "enabled": bool(payload.get("enabled", True)),
            "interval_seconds": interval_seconds,
            "owner": str(payload.get("owner", "")).strip() or "Threat Intel Team",
            "business_unit": str(payload.get("business_unit", "")).strip() or "Security Operations",
            "description": str(payload.get("description", "")).strip(),
            "webhook_url": str(payload.get("webhook_url", "")).strip(),
            "demo_mode": bool(payload.get("demo_mode", False)),
            "tags": [str(item).strip() for item in payload.get("tags", []) if str(item).strip()],
            "assets": [str(item).strip() for item in payload.get("assets", []) if str(item).strip()],
        }
