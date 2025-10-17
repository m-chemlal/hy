"""Simple firewall integration for automatic blocking of IP addresses."""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

import argparse
import subprocess

from config.loader import load_settings
from logs.audit import AuditLogger


SUPPORTED_BACKENDS = {"ufw": ["ufw", "deny"]}


def block_ip(ip: str, settings_path: Path = Path("config/settings.yaml")) -> None:
    settings = load_settings(settings_path)
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
        logger.log_event("response_error", {"ip": ip, "reason": str(exc)})
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
