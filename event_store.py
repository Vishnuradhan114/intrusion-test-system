"""
event_store.py
---------------
A tiny append-only JSON-lines event log, with a thread lock so the Flask
app (possibly multi-threaded) can log events from many requests safely.

Why JSONL instead of a database?  This is a 5th-semester demo project
meant to run for free on Render's free tier with zero external services.
A flat file is simple, needs no setup, and is plenty fast for a
classroom-scale demo. (For a production system you'd swap this for a
real database without changing the rest of the code much.)
"""

import json
import os
import threading
from datetime import datetime


class EventStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        if not os.path.exists(self.path):
            open(self.path, "a").close()

    def log(self, event: dict):
        event.setdefault("timestamp", datetime.utcnow().isoformat())
        line = json.dumps(event)
        with self._lock:
            with open(self.path, "a") as f:
                f.write(line + "\n")

    def all_events(self):
        with self._lock:
            if not os.path.exists(self.path):
                return []
            with open(self.path, "r") as f:
                lines = f.readlines()
        events = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def tail(self, n: int = 100):
        return self.all_events()[-n:]

    def since(self, minutes: int):
        """Return events from the last `minutes` minutes."""
        cutoff = datetime.utcnow().timestamp() - minutes * 60
        result = []
        for e in self.all_events():
            try:
                ts = datetime.fromisoformat(e["timestamp"]).timestamp()
            except Exception:
                continue
            if ts >= cutoff:
                result.append(e)
        return result
