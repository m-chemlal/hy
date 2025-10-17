"""Run anomaly detection against parsed scan results using the baseline model."""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

import argparse
import csv
import datetime as dt
import json
from typing import Any, Dict, Iterable, List, Tuple

from config.loader import load_settings
from logs.audit import AuditLogger

SEVERITY_LEVELS = [
    (0.85, "critical"),
    (0.7, "high"),
    (0.55, "medium"),
    (0.0, "low"),
]


def read_csv_rows(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return [row for row in reader]


def load_model(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Model not found at {path}. Train the model first.")
    return json.loads(path.read_text(encoding="utf-8"))


def score_components(record: Dict[str, Any], model: Dict[str, Any]) -> List[Tuple[str, float, str]]:
    port_counts = model.get("port_counts", {})
    service_counts = model.get("service_counts", {})
    product_counts = model.get("product_counts", {})
    combo_counts = model.get("combo_counts", {})
    totals = model.get("totals", {})

    port = str(record.get("port", "0"))
    service = (record.get("service") or "unknown").lower()
    product = (record.get("product") or "unknown").lower()
    combo_key = f"{service}|{port}"

    max_port = max(totals.get("max_port_count", 1), 1)
    max_service = max(totals.get("max_service_count", 1), 1)
    max_product = max(totals.get("max_product_count", 1), 1)
    max_combo = max(totals.get("max_combo_count", 1), 1)

    components: List[Tuple[str, float, str]] = []

    port_freq = port_counts.get(port, 0)
    if port_freq == 0:
        components.append(("port", 0.6, f"Port {port} not seen during training"))
    else:
        rarity = 1 - (port_freq / max_port)
        components.append(("port", 0.4 * rarity, f"Port {port} rarity score {rarity:.2f}"))

    service_freq = service_counts.get(service, 0)
    if service_freq == 0:
        components.append(("service", 0.5, f"Service '{service}' unseen during training"))
    else:
        rarity = 1 - (service_freq / max_service)
        components.append(("service", 0.3 * rarity, f"Service '{service}' rarity score {rarity:.2f}"))

    product_freq = product_counts.get(product, 0)
    if product_freq == 0:
        components.append(("product", 0.3, f"Product '{product}' unseen during training"))
    else:
        rarity = 1 - (product_freq / max_product)
        components.append(("product", 0.2 * rarity, f"Product '{product}' rarity score {rarity:.2f}"))

    combo_freq = combo_counts.get(combo_key, 0)
    if combo_freq == 0:
        components.append(("combo", 0.4, f"Combination {service}/{port} never observed"))
    else:
        rarity = 1 - (combo_freq / max_combo)
        components.append(("combo", 0.2 * rarity, f"Combination {service}/{port} rarity {rarity:.2f}"))

    return components


def aggregate_score(components: Iterable[Tuple[str, float, str]]) -> Tuple[float, List[Dict[str, Any]]]:
    explanations = []
    score = 0.0
    for feature, value, reason in components:
        score += value
        explanations.append({"feature": feature, "impact": round(value, 3), "reason": reason})
    return min(score, 1.0), explanations


def score_to_severity(score: float) -> str:
    for threshold, label in SEVERITY_LEVELS:
        if score >= threshold:
            return label
    return "info"


def detect(data_path: Path, settings_path: Path) -> Path:
    settings = load_settings(settings_path)
    ai_conf = settings.get("ai_engine", {})
    model_path = Path(ai_conf.get("model_path", "ai_engine/models/baseline_model.json"))
    explanation_dir = Path(ai_conf.get("explanation_dir", "logs/explanations"))
    explanation_dir.mkdir(parents=True, exist_ok=True)

    model = load_model(model_path)
    records = read_csv_rows(data_path)
    fallback_mode = model.get("totals", {}).get("records", 0) == 0

    logger = AuditLogger(settings_path)

    detections: List[Dict[str, Any]] = []
    for record in records:
        if fallback_mode:
            anomaly_score = 0.0
            explanation = [
                {
                    "feature": "model",
                    "impact": 0.0,
                    "reason": "Baseline trained without data; anomaly scoring disabled.",
                }
            ]
            severity = "info"
            prediction = False
        else:
            components = score_components(record, model)
            anomaly_score, explanation = aggregate_score(components)
            severity = score_to_severity(anomaly_score)
            threshold = ai_conf.get("anomaly_threshold", 0.6)
            prediction = anomaly_score > threshold

        enriched = {
            **record,
            "anomaly_score": round(anomaly_score, 3),
            "severity": severity,
            "prediction": prediction,
            "explanation": explanation,
        }
        detections.append(enriched)

        if prediction:
            logger.log_event(
                "anomaly_detected",
                {
                    "ip": record.get("ip"),
                    "port": record.get("port"),
                    "service": record.get("service"),
                    "score": anomaly_score,
                    "severity": severity,
                },
            )

    timestamp = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = explanation_dir / f"detections_{timestamp}.json"
    payload = {
        "generated_at": timestamp,
        "detections": detections,
        "metadata": {
            "records_scored": len(records),
            "baseline_records": model.get("totals", {}).get("records", 0),
            "fallback_mode": fallback_mode,
        },
    }

    if not records:
        payload["metadata"]["note"] = (
            "No parsed scan data available; generated informational report."
        )

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect anomalies using the baseline model")
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
