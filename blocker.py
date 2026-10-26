"""
blocker.py
----------
Application-level IP blocking with automatic 24-hour expiry.

Since the target system is deployed on a free cloud host (Render), we do
NOT have access to the underlying OS firewall - Render does not expose
that. So blocking is implemented the way most real web apps do it when
they don't own the host: a before_request check against a blocklist.

The blocklist is persisted to a JSON file so it survives app restarts
(as long as Render's disk for this instance is still alive - on the free
tier this is "best effort", which is fine for a class demo).
"""

import json
import os
import threading
from datetime import datetime, timedelta


class IPBlocker:
    def __init__(self, path: str, block_hours: int = 24):
        self.path = path
        self.block_hours = block_hours
        self._lock = threading.Lock()
        self._data = {}  # ip -> {"blocked_until": iso string, "reason": str}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self._data, f, indent=2)

    def block(self, ip: str, reason: str = "suspicious activity"):
        with self._lock:
            until = datetime.utcnow() + timedelta(hours=self.block_hours)
            self._data[ip] = {
                "blocked_at": datetime.utcnow().isoformat(),
                "blocked_until": until.isoformat(),
                "reason": reason,
            }
            self._save()

    def unblock(self, ip: str):
        with self._lock:
            if ip in self._data:
                del self._data[ip]
                self._save()

    def is_blocked(self, ip: str):
        """Returns the blocked_until datetime if currently blocked, else None."""
        with self._lock:
            entry = self._data.get(ip)
            if not entry:
                return None
            until = datetime.fromisoformat(entry["blocked_until"])
            if datetime.utcnow() >= until:
                # Expired - auto unblock
                del self._data[ip]
                self._save()
                return None
            return until

    def cleanup_expired(self):
        with self._lock:
            now = datetime.utcnow()
            expired = [
                ip for ip, entry in self._data.items()
                if now >= datetime.fromisoformat(entry["blocked_until"])
            ]
            for ip in expired:
                del self._data[ip]
            if expired:
                self._save()

    def list_blocked(self):
        with self._lock:
            return dict(self._data)
