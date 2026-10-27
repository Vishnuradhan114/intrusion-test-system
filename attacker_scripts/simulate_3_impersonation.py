"""
Scenario 3: Impersonation (ettercap-style MITM / session hijack)
            + file copy + malicious file ("backdoor") installation
=====================================================================
Run this on the "attacker" Windows machine:
    python simulate_3_impersonation.py

IMPORTANT - about ettercap and why this script works the way it does:
  Ettercap performs ARP spoofing to intercept traffic between a victim
  and a server ON THE SAME LOCAL NETWORK (Layer 2). Your target system
  is hosted publicly on Render (a cloud server on the internet), so a
  real ARP-spoofing attack against it from a remote attacker is not
  physically possible (and ettercap has no native Windows build - it's
  a Linux tool). What this script DOES simulate is the *end result* of
  a successful ettercap/MITM session-hijack attack: the attacker ends
  up holding a victim's valid session and starts using it from their own
  machine/IP. That reused-session pattern is exactly what the detector
  looks for (see detector.py, RULE 3), and it is the realistic,
  demonstrable signature of impersonation for a publicly hosted target.

  (If you also want to show REAL ARP spoofing for your viva, see
  README.md -> "Optional: real ettercap demo on a local LAN" - that part
  needs two machines on the same Wi-Fi/LAN and a Linux attacker machine,
  e.g. Kali Linux, since ettercap doesn't run natively on Windows.)

What this script does:
  1. "Victim" logs in normally from their own (legit) fake IP.
  2. A few seconds later, the SAME username logs in again from a
     DIFFERENT fake IP (the "attacker", simulating a hijacked session
     obtained via ARP spoofing / packet sniffing).
  3. The attacker IP then downloads (copies) the confidential file AND
     uploads a suspiciously-named file (simulating a backdoor/malicious
     file being installed) - no real malicious code is created or run,
     only the event is logged, by design (see app.py /upload route).

Expected result on the target system:
  - RULE 3 fires (impersonation + file copy + malicious file drop).
  - Email alert sent, attacker fake IP blocked for 24 hours.
"""

import time
from _common import make_session, login, download_file, upload_file, TARGET_URL

VICTIM_IP = "198.51.100.10"
ATTACKER_IP = "198.51.100.66"
USERNAME = "staff"
PASSWORD = "Staff@123"

# Pinned to a daytime hour on purpose: this scenario is about impersonation,
# not about off-hours timing (that's Scenario 2's job). Pinning the hour
# means this demo gives a clean, isolated RULE 3 alert no matter what time
# of day you actually run it.
DAYTIME_HOUR = 12


def main():
    print(f"Target: {TARGET_URL}")

    print(f"Step 1: victim logs in normally from {VICTIM_IP} ...")
    victim = make_session(fake_ip=VICTIM_IP)
    r = login(victim, USERNAME, PASSWORD, fake_hour=DAYTIME_HOUR)
    print(f"  victim login -> status {r.status_code}")

    print("Step 2: (simulating ettercap ARP-spoof capturing the session)")
    time.sleep(2)

    print(f"Step 3: attacker reuses the same account from a different IP {ATTACKER_IP} ...")
    attacker = make_session(fake_ip=ATTACKER_IP)
    r = login(attacker, USERNAME, PASSWORD, fake_hour=DAYTIME_HOUR)
    print(f"  attacker login -> status {r.status_code}")

    print("Step 4: attacker copies the confidential file ...")
    r = download_file(attacker, "confidential_salary_report.txt", fake_hour=DAYTIME_HOUR)
    print(f"  file copy -> status {r.status_code}")

    print("Step 5: attacker installs a malicious/backdoor file (simulated, harmless) ...")
    r = upload_file(attacker, "svchost_update.exe", content=b"SIMULATED-NOT-REAL-MALWARE", fake_hour=DAYTIME_HOUR)
    print(f"  file upload -> status {r.status_code}")

    print("\nDone. Check the target's /admin page and your email inbox.")

if __name__ == "__main__":
    main()
