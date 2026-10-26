"""
_common.py
----------
Shared helpers for the attacker-simulation scripts. Run these from the
"attacker" Windows machine (a different device/laptop than the one
hosting the project, or even the same laptop on a different network -
what matters for the demo is that it's a separate client hitting your
public Render URL).

Edit TARGET_URL below to your actual Render URL before running anything.
"""

import requests

TARGET_URL = "https://YOUR-APP-NAME.onrender.com"  # <-- CHANGE THIS

# DEMO_MODE on the server lets us simulate different attacker IPs and
# different times-of-day using these headers, without needing many
# physical machines. This mirrors coursework convention for demoing IDS
# systems. Turn DEMO_MODE=false on the server once you no longer need this.


def make_session(fake_ip=None):
    s = requests.Session()
    if fake_ip:
        s.headers.update({"X-Test-IP": fake_ip})
    return s


def login(session_obj, username, password, fake_hour=None):
    headers = {}
    if fake_hour is not None:
        headers["X-Test-Hour"] = str(fake_hour)
    return session_obj.post(f"{TARGET_URL}/login", data={
        "username": username, "password": password
    }, headers=headers, allow_redirects=False)


def download_file(session_obj, filename, fake_hour=None):
    headers = {}
    if fake_hour is not None:
        headers["X-Test-Hour"] = str(fake_hour)
    return session_obj.get(f"{TARGET_URL}/files/{filename}", headers=headers)


def upload_file(session_obj, filename, content=b"dummy content", fake_hour=None):
    headers = {}
    if fake_hour is not None:
        headers["X-Test-Hour"] = str(fake_hour)
    files = {"file": (filename, content)}
    return session_obj.post(f"{TARGET_URL}/upload", files=files, headers=headers)
