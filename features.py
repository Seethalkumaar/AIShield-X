import time
from pathlib import Path

class FeatureExtractor:
    def __init__(self):
        self.events = []
        self.window_time = 10  # seconds

    def add_event(self, event):
        self.events.append(event)

    def get_recent_events(self):
        current = time.time()
        return [e for e in self.events if current - e["timestamp"] <= self.window_time]

    def extract(self, file_path: Path, entropy: float):
        recent = self.get_recent_events()

        event_rate = len(recent) / self.window_time if self.window_time > 0 else 0

        suspicious_ext = file_path.suffix.lower() in [
            ".encrypted", ".locked", ".crypto"
        ]

        rename_count = sum(1 for e in recent if e["event"] == "moved")

        return {
            "entropy": entropy,
            "event_rate": event_rate,
            "suspicious_ext": suspicious_ext,
            "rename_count": rename_count
        }