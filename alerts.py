"""
alerts.py
---------
Sends an email alert to the admin whenever the detection engine fires.

WHY HTTPS API INSTEAD OF SMTP:
Render's free tier blocks most outbound TCP connections except on common
web ports (80/443). Traditional SMTP (port 587/465, used by Gmail etc.)
gets blocked there with "[Errno 101] Network is unreachable" - this is a
platform-level restriction, not a bug in this code. Email HTTP APIs (like
Resend, used here) send mail over a normal HTTPS POST request instead, so
they work fine on Render's free plan.

Uses Resend (resend.com) - generous free tier, no credit card needed.
See README.md -> "Resend email setup" for the exact signup steps.

All credentials are read from environment variables so nothing secret is
hard-coded into the project.
"""

import os
import requests
from datetime import datetime

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
# Resend's free/no-domain sending address. Works without any domain setup,
# but can only deliver to the email address you signed up to Resend with -
# which is exactly what we want here (alerts go to the admin/you).
RESEND_FROM = os.environ.get("RESEND_FROM", "onboarding@resend.dev")
ALERT_TO = os.environ.get("ALERT_TO_EMAIL", "")

RESEND_API_URL = "https://api.resend.com/emails"


def send_alert_email(alert: dict):
    if not RESEND_API_KEY or not ALERT_TO:
        print("[WARN] RESEND_API_KEY / ALERT_TO_EMAIL not set - skipping email, see README.")
        return

    subject = f"[SECURITY ALERT] {alert['rule']} detected from {alert['ip']}"
    body_text = (
        f"Intrusion Test System - Security Alert\n"
        f"=======================================\n\n"
        f"Rule triggered : {alert['rule']}\n"
        f"Attacker IP    : {alert['ip']}\n"
        f"Detected at    : {datetime.utcnow().isoformat()} UTC\n\n"
        f"Details:\n{alert['message']}\n\n"
        f"Action taken   : This IP has been blocked for 24 hours.\n\n"
        f"-- Automated alert from your Intrusion Test & Detection System"
    )

    payload = {
        "from": RESEND_FROM,
        "to": [ALERT_TO],
        "subject": subject,
        "text": body_text,
    }
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
    }

    resp = requests.post(RESEND_API_URL, json=payload, headers=headers, timeout=15)
    if resp.status_code >= 400:
        print(f"[WARN] Resend API error {resp.status_code}: {resp.text}")
        return

    print(f"[INFO] Alert email sent to {ALERT_TO} for rule '{alert['rule']}'")
