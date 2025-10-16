"""Streamlit dashboard for TRUSTED AI SOC LITE."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Trusted AI SOC Lite", layout="wide", page_icon="🛡️")

DASHBOARD_STYLE = """
<style>
    .block-container {
        padding-top: 1rem;
        padding-bottom: 0;
        background-color: #0f172a;
        color: #f8fafc;
    }
    .stMetric {
        background-color: #1e293b;
        padding: 1rem;
        border-radius: 0.75rem;
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.5);
    }
    .metric-container {
        display: flex;
        gap: 1rem;
    }
    .metric-card {
        flex: 1;
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        padding: 1.5rem;
        border-radius: 1rem;
        border: 1px solid rgba(148, 163, 184, 0.2);
    }
    .section-title {
        font-size: 1.2rem;
        color: #93c5fd;
        margin-bottom: 0.5rem;
    }
    .alert-card {
        background-color: #1e293b;
        padding: 1rem;
        border-radius: 0.75rem;
        margin-bottom: 0.5rem;
        border-left: 4px solid #38bdf8;
    }
    .alert-critical { border-color: #ef4444; }
    .alert-high { border-color: #f97316; }
    .alert-medium { border-color: #facc15; }
    .alert-low { border-color: #22c55e; }
</style>
"""

st.markdown(DASHBOARD_STYLE, unsafe_allow_html=True)

st.title("🛡️ TRUSTED AI SOC LITE")
st.caption("Autonomous and explainable SOC powered by Nmap, Wazuh and AI")

LOGS_DIR = Path("logs")
EXPLANATIONS_DIR = LOGS_DIR / "explanations"


@st.cache_data(show_spinner=False)
def load_detections() -> Dict:
    files = sorted(EXPLANATIONS_DIR.glob("detections_*.json"), reverse=True)
    if not files:
        return {"detections": []}
    return json.loads(files[0].read_text(encoding="utf-8"))


@st.cache_data(show_spinner=False)
def load_explanations() -> Dict:
    path = EXPLANATIONS_DIR / "xai_explanations.json"
    if not path.exists():
        return {"explanations": []}
    return json.loads(path.read_text(encoding="utf-8"))


def severity_color(severity: str) -> str:
    return {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#facc15",
        "low": "#22c55e",
    }.get(severity, "#38bdf8")


detections = load_detections().get("detections", [])
explanations_map = {
    (item.get("ip"), item.get("port")): item.get("explanation", [])
    for item in load_explanations().get("explanations", [])
}

high = sum(1 for d in detections if d.get("severity") == "high")
medium = sum(1 for d in detections if d.get("severity") == "medium")
critical = sum(1 for d in detections if d.get("severity") == "critical")

col1, col2, col3 = st.columns(3)
col1.metric("Vulnerabilities Detected", len(detections), help="Total anomalies flagged by the AI")
col2.metric("High Severity", high)
col3.metric("Medium Severity", medium)

st.divider()

left_col, right_col = st.columns([2, 1])

with left_col:
    st.markdown('<div class="section-title">AI Analysis</div>', unsafe_allow_html=True)
    if detections:
        df = pd.DataFrame(detections)
        st.bar_chart(df.groupby("service")["anomaly_score"].mean())
    else:
        st.info("No detections available. Run the pipeline to populate data.")

    st.markdown('<div class="section-title">Real-Time Alerts</div>', unsafe_allow_html=True)
    if detections:
        for det in detections[:5]:
            severity = det.get("severity", "low")
            st.markdown(
                f'<div class="alert-card alert-{severity}"><strong>{severity.upper()}</strong> '
                f"Anomaly detected on {det.get('ip')}:{det.get('port')} ({det.get('service')})" \
                f" — score {det.get('anomaly_score'):.2f}</div>",
                unsafe_allow_html=True,
            )
    else:
        st.success("All clear! No anomalies detected in the latest scan.")

with right_col:
    st.markdown('<div class="section-title">Recent Scans</div>', unsafe_allow_html=True)
    scans = sorted((LOGS_DIR / "scans").glob("*") , reverse=True)[:5]
    for scan in scans:
        st.text(scan.name)

    st.markdown('<div class="section-title">Automated Actions</div>', unsafe_allow_html=True)
    audit_path = Path("logs/audit.json")
    if audit_path.exists():
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        for event in audit.get("events", [])[-5:][::-1]:
            st.markdown(
                f"<div class='alert-card'><strong>{event['type']}</strong><br/>{event['timestamp']}</div>",
                unsafe_allow_html=True,
            )
    else:
        st.write("No automated actions logged yet.")

st.divider()

st.markdown('<div class="section-title">Audit Log</div>', unsafe_allow_html=True)
if Path("logs/audit.json").exists():
    audit_df = pd.json_normalize(json.loads(Path("logs/audit.json").read_text(encoding="utf-8"))["events"])
    st.dataframe(audit_df.tail(10))
else:
    st.write("Audit log not found. Run the detection pipeline to generate entries.")
