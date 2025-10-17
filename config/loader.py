"""Utility helpers for loading project configuration without external dependencies."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def load_settings(path: Path) -> Dict[str, Any]:
    """Load configuration data from a JSON/YAML file.

    The project ships its configuration as JSON so we can keep the loader free
    from third-party dependencies. JSON is a valid subset of YAML which keeps
    backwards compatibility with the previous ``.yaml`` extension.
    """

    text = path.read_text(encoding="utf-8") if path.exists() else "{}"
    text = text.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Unable to parse configuration file at {path}: {exc}") from exc


__all__ = ["load_settings"]
