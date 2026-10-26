"""
detector.py
-----------
The heart of the project: three detection rules that look at the event
stream produced by app.py and decide when "suspicious activity" has
happened. Each rule maps directly to one of the 3 required attack
scenarios.

  RULE 1 - Brute force attack + file access
      >= BRUTE_FORCE_THRESHOLD failed logins from the same IP within
      BRUTE_FORCE_WINDOW_MIN minutes, followed by a successful login
      from that IP, followed by a file access -> flagged.

  RULE 2 - Safe login but off-hours + confidential file access
      A *successful* login (correct password - "safe login") that
      happens outside business hours, followed by access to the
      CONFIDENTIAL file -> flagged. A normal daytime login, or an
      off-hours login that never touches the confidential file, is NOT
      flagged - this is what makes the rule about *behaviour*, not just
      the clock.

  RULE 3 - Impersonation (ettercap-style MITM / session hijack)
           + file copy + malicious file drop
      The same username's session is used from TWO different IPs within
      a short window (IMPERSONATION_WINDOW_MIN) WITHOUT a logout in
      between. This is the observable fingerprint of what an ARP-spoof /
      MITM tool like ettercap achieves in real life: the attacker
      captures a victim's valid session and reuses it from their own
      machine. If, during that second IP's activity, there is also a
      FILE_ACCESS (copy) and a FILE_UPLOAD (simulated backdoor/malicious
      file drop) -> flagged as impersonation + exfiltration + malicious
      file install.

Each rule only fires ONCE per IP per time window (so you don't get 50
duplicate emails for one brute-force run) using an "already alerted"
cache that resets when the IP's block expires.
"""

import threading
from datetime import datetime, timedelta

BRUTE_FORCE_THRESHOLD = 5          # failed logins
BRUTE_FORCE_WINDOW_MIN = 2         # within this many minutes
POST_LOGIN_FILE_WINDOW_MIN = 5     # file access must follow within this long

IMPERSONATION_WINDOW_MIN = 10      # same user, 2 IPs, within this window


class DetectionEngine:
    def __init__(self, event_store, blocker, on_attack_detected,
                 business_start_hour=9, business_end_hour=18):
        self.events = event_store
        self.blocker = blocker
        self.on_attack_detected = on_attack_detected
        self.business_start_hour = business_start_hour
        self.business_end_hour = business_end_hour
        self._lock = threading.Lock()
        self._alerted = set()  # (rule, ip) already alerted & currently blocked

    # ----------------------------------------------------------------
    def evaluate_now(self):
        with self._lock:
            events = self.events.since(minutes=max(
                BRUTE_FORCE_WINDOW_MIN + POST_LOGIN_FILE_WINDOW_MIN,
                IMPERSONATION_WINDOW_MIN,
            ) + 1)

            self._check_brute_force(events)
            self._check_off_hours(events)
            self._check_impersonation(events)

            # allow re-alerting once a previously blocked IP is unblocked
            self._alerted = {
                (rule, ip) for (rule, ip) in self._alerted
                if self.blocker.is_blocked(ip)
            }

    # ----------------------------------------------------------------
    # RULE 1 - brute force + file access
    # ----------------------------------------------------------------
    def _check_brute_force(self, events):
        by_ip = {}
        for e in events:
            if e.get("type") in ("LOGIN_FAIL", "LOGIN_SUCCESS", "FILE_ACCESS"):
                by_ip.setdefault(e["ip"], []).append(e)

        for ip, ip_events in by_ip.items():
            if ("RULE1_BRUTE_FORCE", ip) in self._alerted:
                continue

            ip_events.sort(key=lambda e: e["timestamp"])
            fails = [e for e in ip_events if e["type"] == "LOGIN_FAIL"]
            successes = [e for e in ip_events if e["type"] == "LOGIN_SUCCESS"]
            file_accesses = [e for e in ip_events if e["type"] == "FILE_ACCESS"]

            if len(fails) < BRUTE_FORCE_THRESHOLD or not successes or not file_accesses:
                continue

            # find a burst of >= threshold fails within the window
            fail_times = [datetime.fromisoformat(f["timestamp"]) for f in fails]
            burst_found = False
            for i in range(len(fail_times) - BRUTE_FORCE_THRESHOLD + 1):
                window_start = fail_times[i]
                window_end = fail_times[i + BRUTE_FORCE_THRESHOLD - 1]
                if (window_end - window_start) <= timedelta(minutes=BRUTE_FORCE_WINDOW_MIN):
                    burst_found = True
                    burst_end_time = window_end
                    break
            if not burst_found:
                continue

            # a success after the burst, then a file access shortly after that
            success_after = [s for s in successes
                              if datetime.fromisoformat(s["timestamp"]) >= burst_end_time]
            if not success_after:
                continue
            success_time = datetime.fromisoformat(success_after[0]["timestamp"])

            file_after = [f for f in file_accesses
                          if datetime.fromisoformat(f["timestamp"]) >= success_time
                          and datetime.fromisoformat(f["timestamp"]) <= success_time + timedelta(minutes=POST_LOGIN_FILE_WINDOW_MIN)]
            if not file_after:
                continue

            self._fire("RULE1_BRUTE_FORCE", ip, (
                f"{len(fails)} failed login attempts within "
                f"{BRUTE_FORCE_WINDOW_MIN} min, followed by a successful "
                f"login and access to '{file_after[0]['filename']}'. "
                f"This matches a brute-force attack pattern."
            ))

    # ----------------------------------------------------------------
    # RULE 2 - off-hours login + confidential file access
    # ----------------------------------------------------------------
    def _check_off_hours(self, events):
        by_ip = {}
        for e in events:
            if e.get("type") in ("LOGIN_SUCCESS", "FILE_ACCESS"):
                by_ip.setdefault(e["ip"], []).append(e)

        for ip, ip_events in by_ip.items():
            if ("RULE2_OFF_HOURS", ip) in self._alerted:
                continue

            ip_events.sort(key=lambda e: e["timestamp"])
            off_hour_logins = [
                e for e in ip_events
                if e["type"] == "LOGIN_SUCCESS" and not self._is_business_hour(e.get("hour"))
            ]
            if not off_hour_logins:
                continue

            for login in off_hour_logins:
                login_time = datetime.fromisoformat(login["timestamp"])
                confidential_after = [
                    e for e in ip_events
                    if e["type"] == "FILE_ACCESS"
                    and e.get("confidential")
                    and datetime.fromisoformat(e["timestamp"]) >= login_time
                    and datetime.fromisoformat(e["timestamp"]) <= login_time + timedelta(minutes=POST_LOGIN_FILE_WINDOW_MIN)
                ]
                if confidential_after:
                    self._fire("RULE2_OFF_HOURS", ip, (
                        f"User '{login.get('username')}' logged in successfully "
                        f"at hour={login.get('hour')} (outside business hours "
                        f"{self.business_start_hour}:00-{self.business_end_hour}:00) "
                        f"and then accessed the confidential file "
                        f"'{confidential_after[0]['filename']}'."
                    ))
                    break

    def _is_business_hour(self, hour):
        if hour is None:
            return True  # fail open on bad data - don't false-positive
        return self.business_start_hour <= hour < self.business_end_hour

    # ----------------------------------------------------------------
    # RULE 3 - impersonation / session hijack + file copy + backdoor drop
    # ----------------------------------------------------------------
    def _check_impersonation(self, events):
        by_user = {}
        for e in events:
            if e.get("type") in ("SESSION_START", "FILE_ACCESS", "FILE_UPLOAD"):
                uname = e.get("username")
                if uname:
                    by_user.setdefault(uname, []).append(e)

        for username, u_events in by_user.items():
            u_events.sort(key=lambda e: e["timestamp"])
            sessions = [e for e in u_events if e["type"] == "SESSION_START"]
            if len(sessions) < 2:
                continue

            # look for two SESSION_STARTs from different IPs close together
            for i in range(len(sessions) - 1):
                s1, s2 = sessions[i], sessions[i + 1]
                if s1["ip"] == s2["ip"]:
                    continue
                t1 = datetime.fromisoformat(s1["timestamp"])
                t2 = datetime.fromisoformat(s2["timestamp"])
                if (t2 - t1) > timedelta(minutes=IMPERSONATION_WINDOW_MIN):
                    continue

                suspect_ip = s2["ip"]
                if ("RULE3_IMPERSONATION", suspect_ip) in self._alerted:
                    continue

                # does the second (suspect) IP copy a file AND drop/upload one?
                window_end = t2 + timedelta(minutes=IMPERSONATION_WINDOW_MIN)
                copies = [
                    e for e in u_events
                    if e["type"] == "FILE_ACCESS" and e["ip"] == suspect_ip
                    and t2 <= datetime.fromisoformat(e["timestamp"]) <= window_end
                ]
                uploads = [
                    e for e in u_events
                    if e["type"] == "FILE_UPLOAD" and e["ip"] == suspect_ip
                    and t2 <= datetime.fromisoformat(e["timestamp"]) <= window_end
                ]

                if copies and uploads:
                    self._fire("RULE3_IMPERSONATION", suspect_ip, (
                        f"User '{username}' had an active session from "
                        f"{s1['ip']}, then a NEW session for the same user "
                        f"appeared from a different IP {suspect_ip} within "
                        f"{IMPERSONATION_WINDOW_MIN} min (classic signature of "
                        f"session hijack via MITM / ARP spoofing, e.g. ettercap). "
                        f"That second IP then copied '{copies[0]['filename']}' "
                        f"and uploaded/dropped a file '{uploads[0]['filename']}' "
                        f"(possible backdoor/malicious file installation)."
                    ))

    # ----------------------------------------------------------------
    def _fire(self, rule, ip, message):
        self._alerted.add((rule, ip))
        self.on_attack_detected({"rule": rule, "ip": ip, "message": message})
