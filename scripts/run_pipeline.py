"""End-to-end orchestration script for TRUSTED AI SOC LITE."""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

import argparse

from config.loader import load_settings
from scanner.nmap_scan import run_scan
from scanner.parse_results import parse_results, write_csv
from ai_engine.train_model import train_model
from ai_engine.detect_anomalies import detect
from ai_engine.xai_explain import generate_explanations


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the full SOC Lite pipeline")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/settings.yaml"),
        help="Path to the settings file",
    )
    parser.add_argument(
        "--retrain",
        action="store_true",
        help="Force model retraining even if a model already exists",
    )
    args = parser.parse_args()

    settings = load_settings(args.config)
    ai_conf = settings.get("ai_engine", {})
    model_path = Path(ai_conf.get("model_path", "ai_engine/models/baseline_model.json"))

    scan_path = run_scan(args.config)
    records = parse_results(Path(scan_path))
    parsed_csv = Path("logs/parsed.csv")
    write_csv(records, parsed_csv)

    if args.retrain or not model_path.exists():
        train_model(parsed_csv, args.config)

    detections_path = detect(parsed_csv, args.config)
    generate_explanations(parsed_csv, args.config, detections_path)


if __name__ == "__main__":
    main()
