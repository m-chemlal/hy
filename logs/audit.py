"""Audit logging utilities for TRUSTED AI SOC LITE."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import yaml


class AuditLogger:
    """Lightweight audit logger storing events both in JSON and NDJSON."""

    def __init__(self, settings_path: Path = Path("config/settings.yaml")) -> None:
        with settings_path.open("r", encoding="utf-8") as fh:
            settings = yaml.safe_load(fh) or {}
        audit_conf = settings.get("audit", {})
        self.audit_path = Path(audit_conf.get("audit_log", "logs/audit.json"))
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.ndjson_path = Path(audit_conf.get("wazuh_event_log", "logs/wazuh_events.ndjson"))
        self.ndjson_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.audit_path.exists():
            with self.audit_path.open("w", encoding="utf-8") as fh:
                json.dump({"events": []}, fh, indent=2)

    def _now(self) -> str:
        return datetime.now(tz=timezone.utc).isoformat()

    def log_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        event = {"timestamp": self._now(), "type": event_type, "payload": payload}

        # Append to JSON list
        with self.audit_path.open("r+", encoding="utf-8") as fh:
            data = json.load(fh)
            data.setdefault("events", []).append(event)
            fh.seek(0)
            json.dump(data, fh, indent=2)
            fh.truncate()

        # Append to NDJSON for Wazuh ingestion
        with self.ndjson_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
