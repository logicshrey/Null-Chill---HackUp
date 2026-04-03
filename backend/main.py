from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

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


@app.on_event("startup")
def startup_event() -> None:
    engine.bootstrap()


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


@app.post("/collect-intel")
def collect_intelligence(payload: CollectIntelRequest) -> dict[str, Any]:
    try:
        return engine.collect_external_intelligence(payload.query, persist=payload.persist, demo=payload.demo)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"External intelligence collection failed: {exc}") from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
