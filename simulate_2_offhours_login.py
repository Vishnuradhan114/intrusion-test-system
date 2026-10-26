"""
Scenario 2: Safe (correct) login but at an UNUSUAL time + confidential
file access
========================================================================
Run this on the "attacker" Windows machine:
    python simulate_2_offhours_login.py

What it does:
  1. Logs in with the CORRECT password for 'staff' (a "safe" login -
     no brute force, no wrong guesses) but tags the request with
     X-Test-Hour=2 (2 AM), simulating a login at an unusual/off-hours
     time - e.g. a stolen-but-valid credential used outside normal
     working hours.
  2. Immediately accesses the confidential file.

Expected result on the target system:
  - RULE 2 fires (off-hours login + confidential file access).
  - You get an email alert and this fake IP gets blocked for 24 hours.

Note: a normal daytime login, or an off-hours login that never touches
the confidential file, will NOT trigger this rule - that's intentional,
it's meant to catch suspicious *behaviour*, not just the clock.
"""

from _common import make_session, login, download_file, TARGET_URL

ATTACKER_IP = "203.0.113.77"
USERNAME = "staff"
PASSWORD = "Staff@123"       # correct password - this is a "safe" login
FAKE_HOUR = 2                # 2 AM - outside business hours (9-18)

def main():
    print(f"Target: {TARGET_URL}")
    print(f"Simulating an off-hours but valid login from fake IP {ATTACKER_IP} at hour={FAKE_HOUR}...")
    s = make_session(fake_ip=ATTACKER_IP)

    r = login(s, USERNAME, PASSWORD, fake_hour=FAKE_HOUR)
    print(f"  login -> status {r.status_code}")

    print("Accessing the CONFIDENTIAL file at the same off-hour...")
    r = download_file(s, "confidential_salary_report.txt", fake_hour=FAKE_HOUR)
    print(f"  file access -> status {r.status_code}")

    print("\nDone. Check the target's /admin page and your email inbox.")

if __name__ == "__main__":
    main()
