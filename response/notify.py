"""Notification utilities for TRUSTED AI SOC LITE."""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

import argparse
import smtplib
from email.message import EmailMessage

from config.loader import load_settings
from logs.audit import AuditLogger


def send_email(subject: str, body: str, settings_path: Path = Path("config/settings.yaml")) -> None:
    settings = load_settings(settings_path)
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
            if email_conf.get("password"):
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
