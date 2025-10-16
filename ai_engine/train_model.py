"""Train the anomaly detection model from parsed Nmap data."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd
import yaml
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

NUMERIC_FEATURES = ["port"]
CATEGORICAL_FEATURES = ["state", "service", "product"]


def load_settings(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_pipeline() -> Pipeline:
    transformers = []
    if NUMERIC_FEATURES:
        transformers.append(("num", StandardScaler(), NUMERIC_FEATURES))
    if CATEGORICAL_FEATURES:
        transformers.append(
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore"),
                CATEGORICAL_FEATURES,
            )
        )
    preprocessor = ColumnTransformer(transformers)
    model = IsolationForest(contamination=0.1, n_estimators=200, random_state=42)
    return Pipeline([("preprocessor", preprocessor), ("model", model)])


def train_model(data_path: Path, settings_path: Path) -> Path:
    settings = load_settings(settings_path)
    ai_conf = settings.get("ai_engine", {})
    model_path = Path(ai_conf.get("model_path", "ai_engine/models/isolation_forest.pkl"))
    model_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(data_path)
    pipeline = build_pipeline()
    pipeline.fit(df)
    joblib.dump(pipeline, model_path)
    return model_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the isolation forest model")
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
