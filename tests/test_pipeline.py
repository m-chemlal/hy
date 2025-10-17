from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ai_engine.detect_anomalies import detect
from ai_engine.train_model import train_model
from ai_engine.xai_explain import generate_explanations
from scanner.parse_results import write_csv


class PipelineIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.config_path = self.tmp_path / "config.json"
        config = {
            "ai_engine": {
                "model_path": str(self.tmp_path / "model.json"),
                "explanation_dir": str(self.tmp_path / "explanations"),
                "anomaly_threshold": 0.3,
            },
            "audit": {
                "audit_log": str(self.tmp_path / "audit.json"),
                "wazuh_event_log": str(self.tmp_path / "wazuh.ndjson"),
            },
        }
        self.config_path.write_text(json.dumps(config), encoding="utf-8")

        self.data_path = self.tmp_path / "parsed.csv"
        records = [
            {"ip": "192.168.0.1", "hostname": "host-a", "port": 22, "state": "open", "service": "ssh", "product": "openssh"},
            {"ip": "192.168.0.2", "hostname": "host-b", "port": 80, "state": "open", "service": "http", "product": "nginx"},
            {"ip": "192.168.0.3", "hostname": "host-c", "port": 443, "state": "open", "service": "https", "product": "apache"},
        ]
        write_csv(records, self.data_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pipeline_end_to_end(self) -> None:
        model_path = train_model(self.data_path, self.config_path)
        self.assertTrue(model_path.exists())

        detection_path = detect(self.data_path, self.config_path)
        self.assertTrue(detection_path.exists())
        detections = json.loads(detection_path.read_text(encoding="utf-8"))
        self.assertIn("detections", detections)
        self.assertGreater(len(detections["detections"]), 0)
        self.assertFalse(detections["metadata"]["fallback_mode"])

        explanations_path = generate_explanations(self.data_path, self.config_path, detection_path)
        self.assertTrue(explanations_path.exists())
        explanations = json.loads(explanations_path.read_text(encoding="utf-8"))
        self.assertIn("explanations", explanations)
        self.assertEqual(len(explanations["explanations"]), len(detections["detections"]))
        self.assertFalse(explanations["metadata"]["fallback_mode"])

    def test_train_with_empty_dataset_creates_default_model(self) -> None:
        empty_csv = self.tmp_path / "empty.csv"
        empty_csv.write_text("ip,hostname,port,state,service,product\n", encoding="utf-8")

        model_path = train_model(empty_csv, self.config_path)
        self.assertTrue(model_path.exists())

        baseline = json.loads(model_path.read_text(encoding="utf-8"))
        self.assertEqual(baseline["totals"]["records"], 0)
        self.assertEqual(baseline["port_counts"], {})

    def test_detection_in_fallback_mode_marks_events_as_informational(self) -> None:
        empty_csv = self.tmp_path / "empty.csv"
        empty_csv.write_text("ip,hostname,port,state,service,product\n", encoding="utf-8")
        train_model(empty_csv, self.config_path)

        detections_path = detect(self.data_path, self.config_path)
        detections = json.loads(detections_path.read_text(encoding="utf-8"))

        self.assertTrue(detections["metadata"]["fallback_mode"])
        severities = {item["severity"] for item in detections["detections"]}
        predictions = {item["prediction"] for item in detections["detections"]}

        self.assertEqual(severities, {"info"})
        self.assertEqual(predictions, {False})

    def test_training_handles_missing_dataset(self) -> None:
        missing_csv = self.tmp_path / "missing.csv"

        model_path = train_model(missing_csv, self.config_path)
        self.assertTrue(model_path.exists())

        baseline = json.loads(model_path.read_text(encoding="utf-8"))
        self.assertTrue(baseline["metadata"]["fallback"])
        self.assertEqual(baseline["totals"]["records"], 0)

    def test_detection_with_missing_csv_creates_empty_report(self) -> None:
        model_path = train_model(self.data_path, self.config_path)
        self.assertTrue(model_path.exists())

        missing_csv = self.tmp_path / "missing.csv"
        detections_path = detect(missing_csv, self.config_path)
        detections = json.loads(detections_path.read_text(encoding="utf-8"))

        self.assertEqual(detections["metadata"]["records_scored"], 0)
        self.assertFalse(detections["metadata"]["fallback_mode"])
        self.assertIn("note", detections["metadata"])


if __name__ == "__main__":
    unittest.main()
