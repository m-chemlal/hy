"""Simple firewall integration for automatic blocking of IP addresses."""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import yaml

from logs.audit import AuditLogger


SUPPORTED_BACKENDS = {"ufw": ["ufw", "deny"]}


def block_ip(ip: str, settings_path: Path = Path("config/settings.yaml")) -> None:
    with settings_path.open("r", encoding="utf-8") as fh:
        settings = yaml.safe_load(fh) or {}
    backend = settings.get("response", {}).get("firewall", {}).get("backend", "ufw")
    command = SUPPORTED_BACKENDS.get(backend)
    logger = AuditLogger(settings_path)

    if not command:
        logger.log_event("response_error", {"ip": ip, "reason": f"Unsupported backend {backend}"})
        raise ValueError(f"Unsupported firewall backend: {backend}")

    try:
        subprocess.run(command + [ip], check=True)
        logger.log_event("firewall_block", {"ip": ip, "backend": backend})
    except FileNotFoundError:
        logger.log_event(
            "firewall_block_simulated",
            {"ip": ip, "backend": backend, "detail": "Command not available, simulated"},
        )
    except subprocess.CalledProcessError as exc:
        logger.log_event("response_error", {"ip": ip, "reason": exc.stderr.decode("utf-8") if exc.stderr else str(exc)})
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Block an IP using configured firewall backend")
    parser.add_argument("ip", help="IP address to block")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/settings.yaml"),
        help="Settings file",
    )
    args = parser.parse_args()
    block_ip(args.ip, args.config)


if __name__ == "__main__":
    main()
