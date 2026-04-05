import time

class SessionTracker:
    def __init__(self):
        self.events = []

    def add_event(self, event):
        self.events.append(event)

    def get_stats(self):
        current = time.time()
        recent = [e for e in self.events if current - e["timestamp"] <= 10]

        return {
            "file_count": len(recent),
            "rename_count": sum(1 for e in recent if e["event"] == "moved"),
            "suspicious": sum(1 for e in recent if e.get("suspicious", False))
        }