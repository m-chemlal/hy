"""Notification utilities for TRUSTED AI SOC LITE."""
from __future__ import annotations

import argparse
import smtplib
from email.message import EmailMessage
from pathlib import Path

import yaml

from logs.audit import AuditLogger


def send_email(subject: str, body: str, settings_path: Path = Path("config/settings.yaml")) -> None:
    with settings_path.open("r", encoding="utf-8") as fh:
        settings = yaml.safe_load(fh) or {}
    email_conf = settings.get("response", {}).get("email", {})
    logger = AuditLogger(settings_path)

    if not email_conf.get("enabled", False):
        logger.log_event("notification_skipped", {"subject": subject, "reason": "Email disabled"})
        return

    message = EmailMessage()
    message["From"] = email_conf.get("username")
    message["To"] = email_conf.get("recipient")
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP(email_conf["smtp_server"], email_conf.get("smtp_port", 587)) as smtp:
            smtp.starttls()
            smtp.login(email_conf["username"], email_conf.get("password", ""))
            smtp.send_message(message)
        logger.log_event("notification_sent", {"subject": subject})
    except Exception as exc:  # pragma: no cover - network side effects
        logger.log_event("notification_error", {"subject": subject, "error": str(exc)})
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Send an email notification")
    parser.add_argument("subject", help="Email subject")
    parser.add_argument("body", help="Email body")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/settings.yaml"),
        help="Settings file",
    )
    args = parser.parse_args()
    send_email(args.subject, args.body, args.config)


if __name__ == "__main__":
    main()
