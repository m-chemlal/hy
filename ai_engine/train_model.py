"""Train the anomaly detection baseline from parsed Nmap data."""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

import argparse
import csv
import json
from collections import Counter
from typing import Dict, Iterable, Tuple

from config.loader import load_settings


def read_csv_rows(path: Path) -> Iterable[Dict[str, str]]:
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield row


def _empty_baseline() -> Dict[str, Dict[str, int]]:
    """Return a baseline structure populated with safe defaults.

    When no historical scan data is available we still want to create a model
    file so that downstream commands (``make detect`` / ``make xai``) can run
    without crashing.  The counters are left empty and the ``totals`` section
    is initialised with ``1`` so the scoring code never divides by zero.
    """

    return {
        "totals": {
            "records": 0,
            "max_port_count": 1,
            "max_service_count": 1,
            "max_product_count": 1,
            "max_combo_count": 1,
        },
        "port_counts": {},
        "service_counts": {},
        "product_counts": {},
        "combo_counts": {},
    }


def build_baseline(rows: Iterable[Dict[str, str]]) -> Dict[str, Dict[str, int]]:
    port_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    product_counts: Counter[str] = Counter()
    combo_counts: Counter[Tuple[str, str]] = Counter()

    total = 0
    for row in rows:
        port = str(row.get("port", "0"))
        service = (row.get("service") or "unknown").lower()
        product = (row.get("product") or "unknown").lower()
        port_counts[port] += 1
        service_counts[service] += 1
        product_counts[product] += 1
        combo_counts[(service, port)] += 1
        total += 1

    return {
        "totals": {
            "records": total,
            "max_port_count": max(port_counts.values(), default=1),
            "max_service_count": max(service_counts.values(), default=1),
            "max_product_count": max(product_counts.values(), default=1),
            "max_combo_count": max(combo_counts.values(), default=1),
        },
        "port_counts": dict(port_counts),
        "service_counts": dict(service_counts),
        "product_counts": dict(product_counts),
        "combo_counts": {f"{service}|{port}": count for (service, port), count in combo_counts.items()},
    }


def train_model(data_path: Path, settings_path: Path) -> Path:
    settings = load_settings(settings_path)
    ai_conf = settings.get("ai_engine", {})
    model_path = Path(ai_conf.get("model_path", "ai_engine/models/baseline_model.json"))
    model_path.parent.mkdir(parents=True, exist_ok=True)

    rows = list(read_csv_rows(data_path))
    if not rows:
        if not data_path.exists():
            print(
                f"Training data {data_path} not found. Generated fallback baseline."
            )
        else:
            print(f"No records found in {data_path}. Generated fallback baseline.")
        baseline = _empty_baseline()
    else:
        baseline = build_baseline(rows)

    baseline["metadata"] = {
        "source": str(data_path),
        "records": len(rows),
        "fallback": not rows,
    }
    with model_path.open("w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2)

    return model_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the baseline anomaly model")
    parser.add_argument("data", type=Path, help="CSV exported from parse_results")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/settings.yaml"),
        help="Settings file",
    )
    args = parser.parse_args()
    model_path = train_model(args.data, args.config)
    print(model_path)


if __name__ == "__main__":
    main()
