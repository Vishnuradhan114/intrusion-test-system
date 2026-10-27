"""
Runs all 3 attack simulations back-to-back, with a short pause between
each so you can watch the /admin dashboard update live during your demo
or viva.

Usage (Windows CMD / PowerShell, inside attacker_scripts folder):
    python run_all_demos.py
"""

import time
import simulate_1_bruteforce as s1
import simulate_2_offhours_login as s2
import simulate_3_impersonation as s3

if __name__ == "__main__":
    print("=" * 60)
    print("SCENARIO 1: Brute force + file access")
    print("=" * 60)
    s1.main()

    time.sleep(5)

    print("\n" + "=" * 60)
    print("SCENARIO 2: Off-hours login + confidential file access")
    print("=" * 60)
    s2.main()

    time.sleep(5)

    print("\n" + "=" * 60)
    print("SCENARIO 3: Impersonation + file copy + backdoor install")
    print("=" * 60)
    s3.main()

    print("\nAll 3 scenarios simulated. Open /admin on your target URL and check your inbox.")
