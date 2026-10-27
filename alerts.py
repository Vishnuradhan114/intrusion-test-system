"""
alerts.py
---------
Sends an email alert to the admin whenever the detection engine fires.

Uses Gmail SMTP (smtp.gmail.com:587, STARTTLS) with an "App Password" -
NOT your real Gmail password. See README.md -> "Gmail App Password setup"
for the exact steps.

All credentials are read from environment variables so nothing secret is
hard-coded into the project (important both for safety and because
Render lets you set env vars in its dashboard).
"""

import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")        # your Gmail address
SMTP_PASS = os.environ.get("SMTP_PASS", "")        # Gmail App Password
ALERT_TO = os.environ.get("ALERT_TO_EMAIL", SMTP_USER)  # who receives alerts


def send_alert_email(alert: dict):
    if not SMTP_USER or not SMTP_PASS:
        print("[WARN] SMTP_USER / SMTP_PASS not set - skipping email, see README.")
        return

    subject = f"[SECURITY ALERT] {alert['rule']} detected from {alert['ip']}"
    body = (
        f"Intrusion Test System - Security Alert\n"
        f"=======================================\n\n"
        f"Rule triggered : {alert['rule']}\n"
        f"Attacker IP    : {alert['ip']}\n"
        f"Detected at    : {datetime.utcnow().isoformat()} UTC\n\n"
        f"Details:\n{alert['message']}\n\n"
        f"Action taken   : This IP has been blocked for 24 hours.\n\n"
        f"-- Automated alert from your Intrusion Test & Detection System"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_TO

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [ALERT_TO], msg.as_string())

    print(f"[INFO] Alert email sent to {ALERT_TO} for rule '{alert['rule']}'")
