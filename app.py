"""
Remote Intrusion Test & Detection System
==========================================
5th Semester Mini Project

This single Flask application plays TWO roles at once:
  1. TARGET SYSTEM  - a tiny "company portal" with login + confidential
     files, deployed publicly on Render.com.
  2. DETECTION ENGINE - watches every login/file-access event that
     happens on the target system and raises an alert (email + 24-hour
     IP block) when one of 3 attack patterns is recognised:

        Rule 1 - Brute force login  + file access
        Rule 2 - Off-hours login (correct password) + confidential file access
        Rule 3 - Impersonation / session-hijack (ettercap-style MITM)
                 + file copy + malicious file drop

Everything (target + detector + blocker + mailer) runs as ONE process,
which is exactly how you'd deploy it for free on Render: Render does not
give you OS-level firewall access, so IP blocking is done at the
APPLICATION layer (a before_request check), which is the normal way
web apps implement IP banning when they don't own the underlying host.

Author: <your name>, <your college>, 5th Semester Project
"""

import os
import json
import time
import uuid
import threading
from datetime import datetime, timedelta

from flask import Flask, request, session, redirect, url_for, render_template, send_from_directory, jsonify, abort

try:
    from dotenv import load_dotenv
    load_dotenv()  # loads .env if present (handy for local testing)
except ImportError:
    pass

from blocker import IPBlocker
from alerts import send_alert_email
from detector import DetectionEngine
from event_store import EventStore

# --------------------------------------------------------------------------
# Basic app config
# --------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
FILES_DIR = os.path.join(BASE_DIR, "protected_files")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "change-this-secret-key-before-deploying")

# DEMO_MODE lets the attacker-simulation scripts pretend to come from a
# different IP / different time-of-day WITHOUT needing multiple real
# physical machines or waiting until midnight. This is standard practice
# for classroom / viva demos of IDS systems. Set DEMO_MODE=false in
# production-like use if you don't want this.
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"

# Normal business hours (24h). Logins outside this window are "off-hours".
BUSINESS_START_HOUR = int(os.environ.get("BUSINESS_START_HOUR", "9"))
BUSINESS_END_HOUR = int(os.environ.get("BUSINESS_END_HOUR", "18"))

# Demo users for the target portal. In a real system these would be hashed
# and stored in a DB - kept simple here since this is a teaching project.
USERS = {
    "admin": "Admin@123",
    "staff": "Staff@123",
}

CONFIDENTIAL_FILE = "confidential_salary_report.txt"
DECOY_FILES = ["employee_handbook.txt", "holiday_calendar.txt"]

# Make sure demo protected files exist
def _ensure_demo_files():
    confidential_path = os.path.join(FILES_DIR, CONFIDENTIAL_FILE)
    if not os.path.exists(confidential_path):
        with open(confidential_path, "w") as f:
            f.write(
                "CONFIDENTIAL - INTERNAL USE ONLY\n"
                "=================================\n"
                "Employee Salary Report (DEMO DATA)\n"
                "This file exists only to demonstrate confidential-file\n"
                "access detection for the intrusion-test-system project.\n"
            )
    for name in DECOY_FILES:
        p = os.path.join(FILES_DIR, name)
        if not os.path.exists(p):
            with open(p, "w") as f:
                f.write(f"This is the demo content of {name}.\n")


_ensure_demo_files()

# --------------------------------------------------------------------------
# Core components
# --------------------------------------------------------------------------

event_store = EventStore(os.path.join(DATA_DIR, "events.jsonl"))
blocker = IPBlocker(os.path.join(DATA_DIR, "blocked_ips.json"), block_hours=24)
detector = DetectionEngine(
    event_store=event_store,
    blocker=blocker,
    on_attack_detected=lambda alert: handle_attack(alert),
    business_start_hour=BUSINESS_START_HOUR,
    business_end_hour=BUSINESS_END_HOUR,
)


def handle_attack(alert: dict):
    """Called by the DetectionEngine whenever one of the 3 rules fires."""
    ip = alert["ip"]
    print(f"[ALERT] {alert['rule']} from {ip}: {alert['message']}")

    # 1) Block the attacker IP for 24 hours (application-level block)
    blocker.block(ip, reason=alert["rule"])

    # 2) Send an email alert to the admin
    try:
        send_alert_email(alert)
    except Exception as e:
        print(f"[WARN] Could not send email alert: {e}")

    # 3) Persist the alert itself so /admin can show history
    event_store.log({
        "type": "ALERT",
        "rule": alert["rule"],
        "ip": ip,
        "message": alert["message"],
        "timestamp": datetime.utcnow().isoformat(),
    })


def _client_ip():
    """
    Resolve the 'real' client IP.

    Render sits behind a proxy, so we trust X-Forwarded-For there.
    In DEMO_MODE we additionally allow a custom X-Test-IP header so the
    Windows attacker-simulation scripts can pretend to be a different
    attacker IP without needing several physical machines - this mirrors
    how, in a real ettercap/ARP-spoofing attack, the victim would see
    traffic appear to originate from an unexpected/attacker-controlled
    address.
    """
    if DEMO_MODE and request.headers.get("X-Test-IP"):
        return request.headers.get("X-Test-IP")
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _current_hour():
    """Allow demo scripts to simulate an off-hours login via X-Test-Hour."""
    if DEMO_MODE and request.headers.get("X-Test-Hour"):
        try:
            return int(request.headers.get("X-Test-Hour"))
        except ValueError:
            pass
    return datetime.now().hour


# --------------------------------------------------------------------------
# Security middleware: block IPs that are currently banned
# --------------------------------------------------------------------------

@app.before_request
def _enforce_ip_block():
    ip = _client_ip()
    blocked_until = blocker.is_blocked(ip)
    if blocked_until:
        remaining = blocked_until - datetime.utcnow()
        return jsonify({
            "error": "Access denied",
            "reason": "Your IP has been blocked due to suspicious activity.",
            "blocked_until_utc": blocked_until.isoformat(),
            "retry_after_seconds": max(int(remaining.total_seconds()), 0),
        }), 403


# --------------------------------------------------------------------------
# Routes - the "target system" a normal user (and the attacker) interacts with
# --------------------------------------------------------------------------

@app.route("/")
def home():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return render_template("login.html", demo_mode=DEMO_MODE)


@app.route("/login", methods=["POST"])
def login():
    ip = _client_ip()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    hour = _current_hour()

    success = USERS.get(username) == password

    event_store.log({
        "type": "LOGIN_SUCCESS" if success else "LOGIN_FAIL",
        "ip": ip,
        "username": username,
        "hour": hour,
        "timestamp": datetime.utcnow().isoformat(),
    })

    # Let the detector react immediately (also runs on a background timer)
    detector.evaluate_now()

    if success:
        session["username"] = username
        session["sid"] = str(uuid.uuid4())
        session["login_ip"] = ip
        event_store.log({
            "type": "SESSION_START",
            "ip": ip,
            "username": username,
            "sid": session["sid"],
            "timestamp": datetime.utcnow().isoformat(),
        })
        return redirect(url_for("dashboard"))

    return render_template("login.html", demo_mode=DEMO_MODE, error="Invalid username or password."), 401


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        return redirect(url_for("home"))
    return render_template(
        "dashboard.html",
        username=session["username"],
        confidential_file=CONFIDENTIAL_FILE,
        decoy_files=DECOY_FILES,
    )


@app.route("/files/<path:filename>")
def get_file(filename):
    if not session.get("username"):
        return redirect(url_for("home"))

    ip = _client_ip()
    is_confidential = filename == CONFIDENTIAL_FILE

    event_store.log({
        "type": "FILE_ACCESS",
        "ip": ip,
        "username": session["username"],
        "sid": session.get("sid"),
        "filename": filename,
        "confidential": is_confidential,
        "hour": _current_hour(),
        "timestamp": datetime.utcnow().isoformat(),
    })
    detector.evaluate_now()

    if filename not in [CONFIDENTIAL_FILE] + DECOY_FILES:
        abort(404)
    return send_from_directory(FILES_DIR, filename, as_attachment=True)


@app.route("/upload", methods=["POST"])
def upload_file():
    """
    Simulates 'copying a file in' - e.g. an attacker installing a
    backdoor/malicious file after gaining access. For safety this demo
    endpoint does NOT execute or store anything executable - it only
    records metadata about the uploaded filename so the detector can see
    that a file-drop event happened. No malicious code is produced or
    run anywhere in this project.
    """
    if not session.get("username"):
        return redirect(url_for("home"))

    ip = _client_ip()
    uploaded = request.files.get("file")
    filename = uploaded.filename if uploaded else request.form.get("filename", "unknown_file")

    event_store.log({
        "type": "FILE_UPLOAD",
        "ip": ip,
        "username": session["username"],
        "sid": session.get("sid"),
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
    })
    detector.evaluate_now()

    return jsonify({"status": "received", "filename": filename})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# --------------------------------------------------------------------------
# Admin / monitoring routes
# --------------------------------------------------------------------------

@app.route("/admin")
def admin():
    events = event_store.tail(200)
    blocked = blocker.list_blocked()
    return render_template("admin.html", events=list(reversed(events)), blocked=blocked)


@app.route("/admin/unblock/<ip>", methods=["POST"])
def admin_unblock(ip):
    blocker.unblock(ip)
    return redirect(url_for("admin"))


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


# --------------------------------------------------------------------------
# Background detection loop (also triggered synchronously after each event)
# --------------------------------------------------------------------------

def _background_loop():
    while True:
        try:
            detector.evaluate_now()
            blocker.cleanup_expired()
        except Exception as e:
            print(f"[WARN] background loop error: {e}")
        time.sleep(5)


threading.Thread(target=_background_loop, daemon=True).start()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
