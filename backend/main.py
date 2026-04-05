from __future__ import annotations

import sys
from queue import Empty
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from utils.config import BACKEND_PORT, WATCHLIST_DEFAULT_INTERVAL_SECONDS
from utils.monitoring_runtime import MonitoringEventBus, MonitoringScheduler
from utils.nlp_engine import ThreatIntelligenceEngine


app = FastAPI(
    title="Dark Web Threat Intelligence System",
    version="1.0.0",
    description="AI-powered threat intelligence service for dark web-style text analysis.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ThreatIntelligenceEngine()
event_bus = MonitoringEventBus()
scheduler = MonitoringScheduler(engine, event_bus)


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=3, description="Dark web-style text to analyze.")


class AnalyzeResponse(BaseModel):
    threat_type: str
    risk_level: str
    confidence_score: float
    timestamp: str
    patterns: dict[str, list[str]]
    entities: list[dict[str, str]]
    explanation: list[str]
    primary_classification: dict[str, Any]
    secondary_classification: dict[str, Any]
    semantic_analysis: dict[str, Any]
    enriched_entities: list[dict[str, str]]
    multilingual_analysis: dict[str, Any]
    slang_decoder: dict[str, Any]
    correlation: dict[str, Any]
    impact_assessment: dict[str, Any]
    alert_priority: dict[str, Any]


class CollectIntelRequest(BaseModel):
    query: str = Field(..., min_length=2, description="Organization name or domain to search across public intelligence sources.")
    persist: bool = Field(True, description="Store normalized findings in MongoDB so the existing dashboards can display them.")
    demo: bool = Field(False, description="Generate isolated demo findings instead of querying live providers.")


class WatchlistRequest(BaseModel):
    name: str = Field(..., min_length=2)
    query: str = Field(..., min_length=2)
    enabled: bool = True
    interval_seconds: int = Field(WATCHLIST_DEFAULT_INTERVAL_SECONDS, ge=60)
    owner: str = "Threat Intel Team"
    business_unit: str = "Security Operations"
    description: str = ""
    webhook_url: str = ""
    demo_mode: bool = False
    tags: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)


class CaseUpdateRequest(BaseModel):
    case_status: str | None = None
    owner: str | None = None
    business_unit: str | None = None
    comment: str | None = None


@app.on_event("startup")
def startup_event() -> None:
    engine.bootstrap()
    scheduler.start()


@app.on_event("shutdown")
def shutdown_event() -> None:
    scheduler.stop()


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> dict[str, Any]:
    try:
        result = engine.analyze_text(payload.text, persist=True)
        return {
            "threat_type": result["threat_type"],
            "risk_level": result["risk_level"],
            "confidence_score": result["confidence_score"],
            "timestamp": result["timestamp"],
            "patterns": result["patterns"],
            "entities": result["entities"],
            "explanation": result["explanation"],
            "primary_classification": result["primary_classification"],
            "secondary_classification": result["secondary_classification"],
            "semantic_analysis": result["semantic_analysis"],
            "enriched_entities": result["enriched_entities"],
            "multilingual_analysis": result["multilingual_analysis"],
            "slang_decoder": result["slang_decoder"],
            "correlation": result["correlation"],
            "impact_assessment": result["impact_assessment"],
            "alert_priority": result["alert_priority"],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc


@app.get("/alerts")
def get_alerts(limit: int = 100) -> dict[str, Any]:
    try:
        alerts = engine.get_alerts(limit=limit)
        return {"count": len(alerts), "alerts": alerts, "warning": engine.db.warning}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Alert retrieval failed: {exc}") from exc


@app.get("/stats")
def get_stats() -> dict[str, Any]:
    try:
        return engine.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Stats retrieval failed: {exc}") from exc


@app.get("/monitoring/stats")
def get_monitoring_stats() -> dict[str, Any]:
    try:
        return engine.db.get_monitoring_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Monitoring statistics retrieval failed: {exc}") from exc


@app.get("/health")
def health_check() -> dict[str, str]:
    monitoring = engine.db.get_monitoring_stats()
    return {
        "status": "ok",
        "scheduler": "running",
        "watchlists": str(monitoring.get("enabled_watchlists", 0)),
    }


@app.post("/collect-intel")
def collect_intelligence(payload: CollectIntelRequest) -> dict[str, Any]:
    try:
        response = engine.collect_external_intelligence(payload.query, persist=payload.persist, demo=payload.demo)
        for update in response.get("case_updates", []):
            event_bus.publish(
                {
                    "event_type": "case_updated",
                    "action": update.get("action"),
                    "trigger": "manual_collect",
                    "case": {
                        "id": update.get("case_id"),
                        "title": update.get("title"),
                        "priority": update.get("priority"),
                    },
                }
            )
        return response
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"External intelligence collection failed: {exc}") from exc


@app.get("/cases")
def list_cases(limit: int = 200, status: str | None = None, priority: str | None = None, search: str | None = None) -> dict[str, Any]:
    try:
        cases = engine.db.list_cases(limit=limit, status=status, priority=priority, search=search)
        return {"count": len(cases), "cases": cases}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Case retrieval failed: {exc}") from exc


@app.get("/cases/export")
def export_cases() -> dict[str, Any]:
    return engine.db.export_monitoring_snapshot()


@app.get("/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    case = engine.db.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


@app.patch("/cases/{case_id}")
def update_case(case_id: str, payload: CaseUpdateRequest) -> dict[str, Any]:
    case = engine.db.update_case(case_id, payload.model_dump(exclude_none=True))
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    event_bus.publish(
        {
            "event_type": "case_updated",
            "action": "manual_update",
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
    return case


@app.get("/watchlists")
def list_watchlists() -> dict[str, Any]:
    watchlists = engine.db.list_watchlists(enabled_only=False)
    return {"count": len(watchlists), "watchlists": watchlists}


@app.post("/watchlists")
def create_watchlist(payload: WatchlistRequest) -> dict[str, Any]:
    normalized = scheduler.normalize_watchlist_payload(payload.model_dump())
    watchlist = engine.db.save_watchlist(normalized)
    engine.db.record_audit_event(
        {
            "event_type": "watchlist_created",
            "watchlist_id": watchlist.get("id"),
            "watchlist_name": watchlist.get("name"),
            "query": watchlist.get("query"),
        }
    )
    return watchlist


@app.put("/watchlists/{watchlist_id}")
def update_watchlist(watchlist_id: str, payload: WatchlistRequest) -> dict[str, Any]:
    normalized = scheduler.normalize_watchlist_payload(payload.model_dump())
    watchlist = engine.db.save_watchlist(normalized, watchlist_id=watchlist_id)
    engine.db.record_audit_event(
        {
            "event_type": "watchlist_updated",
            "watchlist_id": watchlist.get("id"),
            "watchlist_name": watchlist.get("name"),
            "query": watchlist.get("query"),
        }
    )
    return watchlist


@app.delete("/watchlists/{watchlist_id}")
def delete_watchlist(watchlist_id: str) -> dict[str, bool]:
    deleted = engine.db.delete_watchlist(watchlist_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Watchlist not found.")
    engine.db.record_audit_event({"event_type": "watchlist_deleted", "watchlist_id": watchlist_id})
    return {"deleted": True}


@app.post("/watchlists/{watchlist_id}/run")
def run_watchlist_now(watchlist_id: str) -> dict[str, Any]:
    try:
        return scheduler.run_watchlist_now(watchlist_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Watchlist run failed: {exc}") from exc


@app.get("/audit-events")
def get_audit_events(limit: int = 100) -> dict[str, Any]:
    events = engine.db.list_audit_events(limit=limit)
    return {"count": len(events), "events": events}


@app.get("/events/stream")
def stream_events() -> StreamingResponse:
    subscriber = event_bus.subscribe()

    def event_generator():
        try:
            while True:
                try:
                    message = subscriber.get(timeout=15)
                    yield f"data: {message}\n\n"
                except Empty:
                    yield "event: heartbeat\ndata: {}\n\n"
        finally:
            event_bus.unsubscribe(subscriber)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=BACKEND_PORT, reload=False)
