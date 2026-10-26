"""
Scenario 1: Brute force attack + file access
=============================================
Run this on the "attacker" Windows machine:
    python simulate_1_bruteforce.py

What it does:
  1. Tries several WRONG passwords for 'admin' rapidly (brute force).
  2. Then logs in with the CORRECT password (as if the attacker finally
     guessed it / cracked it).
  3. Immediately downloads the confidential file.

Expected result on the target system:
  - RULE 1 fires within a few seconds.
  - You get an email alert.
  - This simulated attacker IP is blocked for 24 hours (check /admin).
"""

from _common import make_session, login, download_file, TARGET_URL

ATTACKER_IP = "203.0.113.50"   # fake IP for the demo (TEST-NET-3, safe to use)
USERNAME = "admin"
WRONG_PASSWORDS = ["123456", "password", "admin123", "qwerty", "letmein", "wrongpass1"]
CORRECT_PASSWORD = "Admin@123"

# Pinned to a daytime hour so this demo shows a clean, isolated RULE 1
# alert (and doesn't also accidentally trip RULE 2 if you happen to run
# it at night).
DAYTIME_HOUR = 12

def main():
    print(f"Target: {TARGET_URL}")
    print(f"Simulating brute force from fake IP {ATTACKER_IP} ...")
    s = make_session(fake_ip=ATTACKER_IP)

    for pw in WRONG_PASSWORDS:
        r = login(s, USERNAME, pw, fake_hour=DAYTIME_HOUR)
        print(f"  tried '{pw}' -> status {r.status_code}")

    print("Now trying the correct password...")
    r = login(s, USERNAME, CORRECT_PASSWORD, fake_hour=DAYTIME_HOUR)
    print(f"  tried '{CORRECT_PASSWORD}' -> status {r.status_code}")

    print("Downloading confidential file...")
    r = download_file(s, "confidential_salary_report.txt", fake_hour=DAYTIME_HOUR)
    print(f"  file access -> status {r.status_code}")

    print("\nDone. Check the target's /admin page and your email inbox.")
    print("Try downloading another file now from this same fake IP -")
    print("it should return 403 (blocked) within a few seconds.")

if __name__ == "__main__":
    main()
