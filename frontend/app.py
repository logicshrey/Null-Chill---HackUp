from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from utils.nlp_engine import SIMULATION_TEXTS, ThreatIntelligenceEngine


st.set_page_config(page_title="Dark Web Threat Intelligence", page_icon="🧠", layout="wide")

BACKEND_URL = "http://127.0.0.1:8000"
RISK_COLORS = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#10b981"}


@st.cache_resource(show_spinner=False)
def get_engine() -> ThreatIntelligenceEngine:
    engine = ThreatIntelligenceEngine()
    engine.bootstrap()
    return engine


def backend_available() -> bool:
    try:
        import requests

        response = requests.get(f"{BACKEND_URL}/stats", timeout=1.5)
        return response.ok
    except Exception:
        return False


def analyze_text_with_backend(text: str) -> dict[str, Any]:
    try:
        import requests

        response = requests.post(f"{BACKEND_URL}/analyze", json={"text": text}, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception:
        return get_engine().analyze_text(text, persist=False)


def fetch_backend_alerts() -> list[dict[str, Any]]:
    try:
        import requests

        response = requests.get(f"{BACKEND_URL}/alerts", timeout=10)
        response.raise_for_status()
        return response.json().get("alerts", [])
    except Exception:
        return get_engine().get_alerts(limit=200)


def fetch_backend_stats() -> dict[str, Any]:
    try:
        import requests

        response = requests.get(f"{BACKEND_URL}/stats", timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception:
        return get_engine().get_stats()


def render_risk_badge(risk_level: str) -> None:
    color = RISK_COLORS.get(risk_level, "#64748b")
    st.markdown(
        f"""
        <div style="padding:0.6rem 1rem;border-radius:0.75rem;background:{color};color:white;
        font-weight:700;text-align:center;">
            Risk Level: {risk_level}
        </div>
        """,
        unsafe_allow_html=True,
    )


def flatten_results_for_table(results: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for item in results:
        if "results" in item:
            result = item["results"]
            text = item.get("text", result.get("input_text", ""))
        else:
            result = item
            text = result.get("input_text", "")
        rows.append(
            {
                "text": text,
                "threat_type": result.get("threat_type"),
                "risk_level": result.get("risk_level"),
                "confidence_score": result.get("confidence_score"),
                "timestamp": result.get("timestamp"),
                "organizations": ", ".join(
                    entity["text"] for entity in result.get("entities", []) if entity.get("label") == "ORG"
                ),
            }
        )
    return pd.DataFrame(rows)


def page_analyze_text() -> None:
    st.subheader("Analyze Text")
    default_text = "Admin login credentials for SBI with email ops@sbi.com password=Root@123 available via @broker"
    text = st.text_area("Enter suspicious text", value=default_text, height=180)

    col1, col2 = st.columns([1, 3])
    with col1:
        analyze_clicked = st.button("Analyze Threat", use_container_width=True, type="primary")
    with col2:
        sample = st.selectbox("Try a live sample", SIMULATION_TEXTS)
        if st.button("Load Sample", use_container_width=True):
            st.session_state["loaded_sample"] = sample
            st.rerun()

    if st.session_state.get("loaded_sample"):
        text = st.session_state["loaded_sample"]
        st.code(text)

    if analyze_clicked:
        result = analyze_text_with_backend(text)
        st.session_state.setdefault("analysis_history", []).append(result)

        top1, top2, top3 = st.columns(3)
        top1.metric("Threat Type", result["threat_type"])
        top2.metric("Confidence", f"{result['confidence_score']:.2%}")
        with top3:
            render_risk_badge(result["risk_level"])

        expl_col, signal_col = st.columns([1.2, 1])
        with expl_col:
            st.markdown("### Explainable AI")
            for line in result.get("explanation", []):
                st.write(f"- {line}")
            st.json(result.get("primary_classification", {}), expanded=False)
            st.json(result.get("secondary_classification", {}), expanded=False)
        with signal_col:
            st.markdown("### Threat Signals")
            st.json(result.get("patterns", {}), expanded=False)
            st.json(result.get("entities", []), expanded=False)
            st.json(result.get("semantic_analysis", {}), expanded=False)


def page_upload_dataset() -> None:
    st.subheader("Upload Dataset")
    st.caption("Upload any CSV with a text column for batch analysis.")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if not uploaded:
        return

    dataframe = pd.read_csv(uploaded)
    st.dataframe(dataframe.head(10), use_container_width=True)
    text_column = st.selectbox("Select the text column", dataframe.columns)

    max_rows = st.slider("Rows to analyze", min_value=1, max_value=min(250, len(dataframe)), value=min(50, len(dataframe)))
    if st.button("Run Batch Analysis", type="primary"):
        progress = st.progress(0)
        batch_results = []
        subset = dataframe.head(max_rows).copy()
        for idx, value in enumerate(subset[text_column].fillna("").astype(str).tolist(), start=1):
            batch_results.append(analyze_text_with_backend(value))
            progress.progress(idx / max_rows)

        results_df = flatten_results_for_table(batch_results)
        combined = pd.concat([subset.reset_index(drop=True), results_df], axis=1)
        st.dataframe(combined, use_container_width=True)

        csv_bytes = combined.to_csv(index=False).encode("utf-8")
        st.download_button("Download analyzed CSV", data=csv_bytes, file_name="analyzed_dataset.csv", mime="text/csv")


def page_alerts_dashboard() -> None:
    st.subheader("Alerts Dashboard")
    left, right = st.columns([1, 1])
    with left:
        if st.button("Run Threat Simulation", use_container_width=True):
            simulated = get_engine().simulate_alerts(count=5)
            st.session_state.setdefault("analysis_history", []).extend(simulated)
            st.success("Five simulated alerts generated.")
    with right:
        st.info("The dashboard uses FastAPI when available and falls back to the shared local engine otherwise.")

    alerts = fetch_backend_alerts()
    if not alerts:
        st.warning("No alerts recorded yet. Analyze text or run a simulation to populate the dashboard.")
        return

    alerts_df = flatten_results_for_table(alerts)
    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        selected_risk = st.multiselect("Filter by risk", sorted(alerts_df["risk_level"].dropna().unique().tolist()))
    with filter_col2:
        selected_threat = st.multiselect("Filter by threat", sorted(alerts_df["threat_type"].dropna().unique().tolist()))

    if selected_risk:
        alerts_df = alerts_df[alerts_df["risk_level"].isin(selected_risk)]
    if selected_threat:
        alerts_df = alerts_df[alerts_df["threat_type"].isin(selected_threat)]

    st.dataframe(alerts_df, use_container_width=True)


def page_analytics() -> None:
    st.subheader("Analytics")
    stats = fetch_backend_stats()
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Alerts", stats.get("total_alerts", 0))
    col2.metric("MongoDB", "Connected" if stats.get("mongo_connected") else "Fallback")
    col3.metric("Secondary Model", stats.get("secondary_status", "unknown"))

    threat_distribution = pd.DataFrame(
        list(stats.get("threat_distribution", {}).items()),
        columns=["threat_type", "count"],
    )
    risk_levels = pd.DataFrame(
        list(stats.get("risk_levels", {}).items()),
        columns=["risk_level", "count"],
    )
    entity_frequency = pd.DataFrame(
        list(stats.get("entity_frequency", {}).items()),
        columns=["entity", "count"],
    )
    org_tracking = pd.DataFrame(
        list(stats.get("organization_tracking", {}).items()),
        columns=["organization", "mentions"],
    )

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        if not threat_distribution.empty:
            fig = px.bar(threat_distribution, x="threat_type", y="count", color="threat_type", title="Threat Distribution")
            st.plotly_chart(fig, use_container_width=True)
    with chart_col2:
        if not risk_levels.empty:
            fig = px.pie(risk_levels, names="risk_level", values="count", title="Risk Levels")
            st.plotly_chart(fig, use_container_width=True)

    bottom_col1, bottom_col2 = st.columns(2)
    with bottom_col1:
        if not entity_frequency.empty:
            fig = px.bar(entity_frequency.head(10), x="entity", y="count", color="count", title="Entity Frequency")
            st.plotly_chart(fig, use_container_width=True)
    with bottom_col2:
        if not org_tracking.empty:
            fig = px.bar(org_tracking.head(10), x="organization", y="mentions", color="mentions", title="Organization Tracking")
            st.plotly_chart(fig, use_container_width=True)

    if stats.get("warning"):
        st.warning(stats["warning"])
    metrics = stats.get("model_metrics", {})
    if metrics:
        st.markdown("### Model Metrics")
        st.json(metrics, expanded=False)


def main() -> None:
    st.title("Dark Web Threat Intelligence System")
    st.caption("AI/ML + NLP pipeline for credential leaks, malware sales, phishing, database dumps, and suspicious activity.")

    sidebar_col1, sidebar_col2 = st.sidebar.columns(2)
    with sidebar_col1:
        st.write("Backend")
        st.write("Online" if backend_available() else "Offline")
    with sidebar_col2:
        st.write("Engine")
        st.write("Ready")

    page = st.sidebar.radio(
        "Navigation",
        ["Analyze Text", "Upload Dataset", "Alerts Dashboard", "Analytics"],
    )

    if page == "Analyze Text":
        page_analyze_text()
    elif page == "Upload Dataset":
        page_upload_dataset()
    elif page == "Alerts Dashboard":
        page_alerts_dashboard()
    else:
        page_analytics()


if __name__ == "__main__":
    main()
