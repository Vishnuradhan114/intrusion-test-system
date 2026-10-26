# Remote Intrusion Test & Detection System
### 5th Semester Mini Project — fully free, ready to run

This project is a publicly-hosted "test system" (a small web portal) plus
a built-in **detection engine** that watches for 3 remote-attack patterns,
sends an **email alert**, and **blocks the attacker's IP for 24 hours**.

```
Attacker device (your Windows laptop)  --->  Public test system (Render.com, free)
   runs attacker_scripts/*.py                  app.py: login portal + files
   simulates 3 attack scenarios                + detector.py (3 rules)
                                                + blocker.py (24h IP ban)
                                                + alerts.py (Gmail email)
```

Everything runs on Render's **free tier** (no credit card needed) and the
attacker-simulation scripts run on your **Windows machine**.

---

## 1. What the 3 attack scenarios are, and how detection works

| # | Scenario | How it's detected |
|---|----------|--------------------|
| 1 | **Brute force** login + file access | 5+ failed logins from one IP within 2 minutes, followed by a successful login, followed by a file download |
| 2 | **Off-hours login** (correct password) + confidential file access | A *successful* login outside business hours (default 9 AM–6 PM) followed by access to the confidential file |
| 3 | **Impersonation** (ettercap-style session hijack) + file copy + backdoor install | The same username logged in from **two different IPs** within 10 minutes (no logout in between) — the signature of a stolen/hijacked session — and the second IP then copies a file **and** uploads a suspicious file |

All 3 result in:
- An **email alert** to you with the IP, rule, and details.
- That IP being **blocked for exactly 24 hours** (auto-unblocks after).
- A log entry visible on the `/admin` dashboard.

### A note on ettercap specifically
Ettercap does ARP spoofing on a **local network (same Wi-Fi/LAN)**. Your
target system will be hosted on the public internet (Render), so a real
remote ettercap attack against it isn't physically possible — and
ettercap doesn't even have a native Windows build. So Scenario 3's script
simulates the **realistic end-result** of a successful ettercap/MITM
attack: the attacker ends up using a victim's valid session from their
own IP. That's exactly the pattern real IDS systems look for too. If you
want to additionally demo *real* ARP spoofing for your viva, see
[Section 6](#6-optional-real-ettercap-arp-spoofing-demo-on-a-lan) — that
part needs a Linux attacker machine (e.g. Kali Linux) on the same LAN as
a victim.

---

## 2. Project files

```
intrusion-test-system/
├── app.py                  # Flask app: the target "test system"
├── detector.py              # The 3 detection rules
├── blocker.py                # 24-hour IP blocking
├── alerts.py                  # Email alert sender
├── event_store.py              # Simple event log (JSON lines)
├── requirements.txt
├── Procfile                     # tells Render how to start the app
├── render.yaml                   # optional one-click Render blueprint
├── .env.example                   # copy to .env for local testing
├── templates/                      # login.html, dashboard.html, admin.html
├── protected_files/                 # confidential + decoy files (auto-created)
├── data/                              # events.jsonl, blocked_ips.json (auto-created)
└── attacker_scripts/                    # run these from your Windows attacker PC
    ├── _common.py                         # <- set your Render URL here
    ├── simulate_1_bruteforce.py
    ├── simulate_2_offhours_login.py
    ├── simulate_3_impersonation.py
    └── run_all_demos.py                      # runs all 3 back-to-back
```

---

## 3. Gmail App Password setup (needed for email alerts)

You **cannot** use your normal Gmail password for SMTP — Google requires
an "App Password".

1. Go to **myaccount.google.com** → **Security**.
2. Turn on **2-Step Verification** (required before App Passwords appear).
3. In the search box at the top, type **"App Passwords"** and open it.
4. Create a new app password — name it e.g. `intrusion-system` — click **Create**.
5. Google shows you a **16-character password** (like `abcd efgh ijkl mnop`).
   Copy it (remove spaces) — you'll paste it into Render as `SMTP_PASS`.

---

## 4. Deploy the target system to Render (free)

1. Create a free account at **render.com**.
2. Put this project folder on GitHub (easiest way for Render to deploy it):
   - Create a new **empty** GitHub repo, e.g. `intrusion-test-system`.
   - Upload/push the contents of this folder to it.
3. On Render: **New +** → **Web Service** → connect that GitHub repo.
4. Settings:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT`
   - **Instance Type**: `Free`
5. Under **Environment** → add these variables:

   | Key | Value |
   |---|---|
   | `APP_SECRET_KEY` | any long random string |
   | `DEMO_MODE` | `true` |
   | `BUSINESS_START_HOUR` | `9` |
   | `BUSINESS_END_HOUR` | `18` |
   | `SMTP_USER` | your Gmail address |
   | `SMTP_PASS` | the 16-character App Password from Section 3 |
   | `ALERT_TO_EMAIL` | the email that should receive alerts (can be same as SMTP_USER) |

6. Click **Create Web Service**. Wait ~2 minutes for the first deploy.
7. Render gives you a public URL like `https://intrusion-test-system.onrender.com`.
   Open it — you should see the **SecurePortal** login page.

> **Free-tier note:** Render's free web services "sleep" after ~15 minutes
> of no traffic and take ~30-50 seconds to wake up on the next request.
> That's normal — just means your very first demo request each session
> will be a bit slow. It does **not** affect the detection logic.

---

## 5. Run the attack simulations from your Windows machine

1. Install Python 3.10+ on Windows if you don't already have it
   (python.org → Download → check "Add to PATH" during install).
2. Open Command Prompt and install the one dependency needed:
   ```
   pip install requests
   ```
3. Open `attacker_scripts\_common.py` in Notepad and change this line to
   your actual Render URL:
   ```python
   TARGET_URL = "https://YOUR-APP-NAME.onrender.com"
   ```
4. Run each scenario (or all of them together):
   ```
   cd attacker_scripts
   python simulate_1_bruteforce.py
   python simulate_2_offhours_login.py
   python simulate_3_impersonation.py
   ```
   or all 3 in one go, with pauses between so you can watch live:
   ```
   python run_all_demos.py
   ```
5. Watch it happen live:
   - Open `https://YOUR-APP-NAME.onrender.com/admin` in a browser — it
     auto-refreshes every 10 seconds and shows the event log, the
     alerts, and the currently-blocked IPs.
   - Check the inbox you set as `ALERT_TO_EMAIL` — you should get 3
     separate alert emails (one per rule).
6. Prove the block works: run a script again for the same fake IP right
   after — you'll get HTTP 403 ("Access denied... blocked") until the
   24-hour window expires (or until you click **Unblock** on `/admin`).

### For your viva / demo
- `/admin` is your live dashboard — keep it open on a second screen.
- Each simulation script prints exactly what it's doing step by step,
  so you can narrate it ("now I'm sending 6 wrong passwords...").
- The `DEMO_MODE` env var is what allows `X-Test-IP` / `X-Test-Hour`
  headers to simulate multiple attacker IPs / times of day from one
  laptop — explain this honestly in your report: it's a standard way to
  demo an IDS without needing a lab full of machines and without
  waiting until 2 AM to test Scenario 2.

---

## 6. Optional: real ettercap ARP-spoofing demo on a LAN

Not required for the project to work, but if you want to show a *real*
MITM attack in your viva as a bonus:

- You need **2 devices on the same Wi-Fi/router** (not the public
  internet): a "victim" machine and an attacker machine running
  **Kali Linux** (ettercap is pre-installed there, or `apt install
  ettercap-graphical` on Debian/Ubuntu).
- Host a **second, local copy** of this Flask app on the victim machine
  (`python app.py`) so both devices can reach it over the LAN.
- On Kali: `sudo ettercap -G` → Sniff → Unified sniffing → pick your
  network interface → Scan for hosts → add the victim and the router as
  Target 1/Target 2 → **Mitm → ARP poisoning** → start sniffing.
- Have the victim log in on their browser; the attacker (on Kali) can
  observe the captured HTTP traffic in ettercap's connection view.
- This demonstrates the *attack technique*; the detection system itself
  only sees the detectable the pattern — a credential/session reused
  from a different IP — which is exactly what `simulate_3_impersonation.py`
  reproduces against your public Render deployment.

---

## 7. Running the target system locally on Windows (optional)

If you also want to run the target system itself on your Windows
machine (in addition to, or instead of, Render):

```
pip install -r requirements.txt
copy .env.example .env
notepad .env        REM fill in SMTP_USER / SMTP_PASS / ALERT_TO_EMAIL
python app.py
```

It starts on `http://localhost:5000`. Point `attacker_scripts/_common.py`
at `http://<your-PC's-LAN-IP>:5000` instead of the Render URL to attack
it from another device on the same network.

---

## 8. Customizing

- Change `BUSINESS_START_HOUR` / `BUSINESS_END_HOUR` env vars to adjust
  what counts as "off-hours" for Rule 2.
- Change `USERS` in `app.py` to add more demo accounts.
- Thresholds (brute-force count/window, impersonation window) are
  constants at the top of `detector.py` if you want to tune sensitivity.
- Set `DEMO_MODE=false` once you're done demoing, to stop honoring the
  `X-Test-IP`/`X-Test-Hour` headers (real deployments shouldn't allow
  clients to claim their own IP).

---

## 9. Safety note

The `/upload` endpoint in this project **never executes or stores
anything as a running program** — it only records the filename of what
was "dropped", purely so the detector has something to react to. No real
backdoor, virus, or malicious payload is created or used anywhere in
this project, by design.
