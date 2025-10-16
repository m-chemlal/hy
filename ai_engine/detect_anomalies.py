"""Run anomaly detection against parsed scan results."""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd
import yaml

from logs.audit import AuditLogger


SEVERITY_LEVELS = [
    (0.85, "critical"),
    (0.7, "high"),
    (0.55, "medium"),
    (0.0, "low"),
]


def load_settings(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def score_to_severity(score: float) -> str:
    for threshold, label in SEVERITY_LEVELS:
        if score >= threshold:
            return label
    return "info"


def detect(data_path: Path, settings_path: Path) -> Path:
    settings = load_settings(settings_path)
    ai_conf = settings.get("ai_engine", {})
    model_path = Path(ai_conf.get("model_path", "ai_engine/models/isolation_forest.pkl"))
    explanation_dir = Path(ai_conf.get("explanation_dir", "logs/explanations"))
    explanation_dir.mkdir(parents=True, exist_ok=True)

    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found at {model_path}. Train the model with ai_engine/train_model.py first."
        )

    df = pd.read_csv(data_path)
    pipeline = joblib.load(model_path)
    decision_scores = pipeline.decision_function(df)
    anomaly_scores = (decision_scores.max() - decision_scores) / (decision_scores.max() - decision_scores.min() + 1e-6)

    results = df.copy()
    results["anomaly_score"] = anomaly_scores
    results["severity"] = results["anomaly_score"].apply(score_to_severity)
    threshold = ai_conf.get("anomaly_threshold", 0.6)
    results["prediction"] = results["anomaly_score"] > threshold

    timestamp = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = explanation_dir / f"detections_{timestamp}.json"
    records = results.to_dict(orient="records")
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump({"generated_at": timestamp, "detections": records}, fh, indent=2)

    # Audit logging per detection
    logger = AuditLogger(settings_path)
    for record in records:
        if record["prediction"]:
            logger.log_event(
                "anomaly_detected",
                {
                    "ip": record.get("ip"),
                    "port": record.get("port"),
                    "service": record.get("service"),
                    "score": record.get("anomaly_score"),
                    "severity": record.get("severity"),
                },
            )

    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect anomalies using the trained model")
    parser.add_argument("data", type=Path, help="CSV exported from parse_results")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/settings.yaml"),
        help="Settings file",
    )
    args = parser.parse_args()
    output = detect(args.data, args.config)
    print(output)


if __name__ == "__main__":
    main()
