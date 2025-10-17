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

        explanations_path = generate_explanations(self.data_path, self.config_path, detection_path)
        self.assertTrue(explanations_path.exists())
        explanations = json.loads(explanations_path.read_text(encoding="utf-8"))
        self.assertIn("explanations", explanations)
        self.assertEqual(len(explanations["explanations"]), len(detections["detections"]))


if __name__ == "__main__":
    unittest.main()
