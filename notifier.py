"""
Notifications vers les analystes SOC (Slack et/ou email).
Les deux canaux sont optionnels : si les variables d'environnement
ne sont pas renseignees, la notification est simplement journalisee.
"""
import logging
import os
import smtplib
from email.mime.text import MIMEText

import requests

logger = logging.getLogger("soar.notifier")

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_FROM = os.getenv("SMTP_FROM", "soc-alert@cdgcapital-lab.local")
SMTP_TO = os.getenv("SMTP_TO", "soc-team@cdgcapital-lab.local")


def notify(subject: str, message: str, severity: str = "medium"):
    logger.info("[NOTIFICATION][%s] %s - %s", severity.upper(), subject, message)

    if SLACK_WEBHOOK_URL:
        try:
            requests.post(
                SLACK_WEBHOOK_URL,
                json={"text": f"*[{severity.upper()}] {subject}*\n{message}"},
                timeout=5,
            )
        except requests.RequestException as exc:
            logger.error("Echec notification Slack : %s", exc)

    if SMTP_HOST:
        try:
            msg = MIMEText(message)
            msg["Subject"] = f"[SOC-CDG][{severity.upper()}] {subject}"
            msg["From"] = SMTP_FROM
            msg["To"] = SMTP_TO
            with smtplib.SMTP(SMTP_HOST, 25, timeout=5) as server:
                server.send_message(msg)
        except Exception as exc:  # noqa: BLE001
            logger.error("Echec notification email : %s", exc)
