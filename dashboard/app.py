"""Console-based dashboard summarising the latest SOC Lite outputs."""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

import json
from textwrap import indent
from typing import Any, Dict, List

LOGS_DIR = Path("logs")
EXPLANATIONS_DIR = LOGS_DIR / "explanations"


def load_json(path: Path, default: Dict | List | None = None):
    if not path.exists():
        return default if default is not None else {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def render_metrics(detections: List[Dict[str, Any]]) -> str:
    total = len(detections)
    severities: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for det in detections:
        severity = det.get("severity", "low")
        severities[severity] = severities.get(severity, 0) + 1
    lines = ["=== TRUSTED AI SOC LITE ===", f"Detections: {total}"]
    for level in ["critical", "high", "medium", "low"]:
        lines.append(f"  {level.title():<8}: {severities.get(level, 0)}")
    return "\n".join(lines)


def render_alerts(detections: List[Dict[str, Any]]) -> str:
    if not detections:
        return "No anomalies detected in the latest run."
    lines = ["--- Recent Alerts ---"]
    for det in detections[:5]:
        lines.append(
            f"[{det.get('severity', 'low').upper()}] {det.get('ip')}:{det.get('port')} {det.get('service', '')}"
            f" — score {float(det.get('anomaly_score', 0)):.2f}"
        )
    return "\n".join(lines)


def render_explanations(explanations: List[Dict[str, Any]]) -> str:
    if not explanations:
        return "No explanations generated yet."
    lines = ["--- Explainability Highlights ---"]
    for item in explanations[:3]:
        reason_lines = [
            f"* {exp['feature']}: {exp.get('reason', 'n/a')} (impact {exp.get('impact', 0)})"
            for exp in item.get("explanation", [])
        ]
        block = "\n".join(reason_lines) or "* No explanation details available"
        lines.append(
            f"{item.get('ip')}:{item.get('port')} [{item.get('severity', 'low')}]\n" + indent(block, "    ")
        )
    return "\n".join(lines)


def render_audit() -> str:
    audit_path = LOGS_DIR / "audit.json"
    audit = load_json(audit_path, default={"events": []})
    events = audit.get("events", [])[-5:]
    if not events:
        return "No audit events recorded."
    lines = ["--- Recent Audit Events ---"]
    for event in events[::-1]:
        lines.append(f"{event.get('timestamp')} :: {event.get('type')} -> {event.get('payload')}")
    return "\n".join(lines)


def main() -> None:
    detection_files = sorted(EXPLANATIONS_DIR.glob("detections_*.json"), reverse=True)
    detections_doc = load_json(detection_files[0], default={"detections": []}) if detection_files else {"detections": []}
    detections = detections_doc.get("detections", [])

    explanations_doc = load_json(EXPLANATIONS_DIR / "xai_explanations.json", default={"explanations": []})
    explanations = explanations_doc.get("explanations", [])

    sections = [
        render_metrics(detections),
        render_alerts(detections),
        render_explanations(explanations),
        render_audit(),
    ]
    print("\n\n".join(sections))


if __name__ == "__main__":
    main()
