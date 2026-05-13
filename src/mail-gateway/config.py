from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


class ConfigError(RuntimeError):
    pass


def load_config(path: str | Path) -> Dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    _validate_config(data)
    return data


def _validate_config(data: Dict[str, Any]) -> None:
    required = ["gateway", "risk_thresholds", "checks", "weights", "content", "urls", "attachments", "adaptive"]
    missing = [name for name in required if name not in data]
    if missing:
        raise ConfigError(f"Missing config sections: {', '.join(missing)}")
    thresholds = data["risk_thresholds"]
    if thresholds["deliver_below"] >= thresholds["quarantine_below"]:
        raise ConfigError("Invalid thresholds: deliver_below must be less than quarantine_below")
