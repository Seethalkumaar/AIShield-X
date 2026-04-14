import time

class SessionTracker:
    def __init__(self):
        self.events = []
        self.start_time = None
        self.last_event_time = None

    def add_event(self, event):
        if self.start_time is None:
            self.start_time = event.get("timestamp", time.time())
        self.last_event_time = event.get("timestamp", time.time())
        self.events.append(event)

    def get_stats(self):
        current = time.time()
        recent = [e for e in self.events if current - e["timestamp"] <= 10]

        session_duration = 0
        if self.start_time is not None and self.last_event_time is not None:
            session_duration = self.last_event_time - self.start_time

        return {
            "file_count": len(recent),
            "rename_count": sum(1 for e in recent if e["event"] == "moved"),
            "suspicious": sum(1 for e in recent if e.get("suspicious", False)),
            "session_events": len(self.events),
            "session_duration": session_duration
        }