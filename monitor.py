import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from entropy import calculate_entropy
from features import FeatureExtractor
from risk_engine import calculate_risk, get_severity, is_ransomware
from logger import log_event
from session import SessionTracker
from mitigation import quarantine_file
from live_log import add_log


class Handler(FileSystemEventHandler):
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.session = SessionTracker()
        self.last_alert = 0
        self.last_processed = {}

    def process(self, path, event_type):
        print("DEBUG: event received", event_type, path)

        if not path.exists() or not path.is_file():
            print("DEBUG: skipped non-file path", path)
            return

        now = time.time()
        path_key = str(path)
        if path_key in self.last_processed and now - self.last_processed[path_key] < 0.5:
            print("DEBUG: skipped duplicate event", path)
            return
        self.last_processed[path_key] = now

        try:
            data = path.read_bytes()[:200000]
            entropy = calculate_entropy(data)

        except FileNotFoundError:
            print(f"DEBUG: file disappeared before processing (likely renamed): {path}")
            return

        try:
            # Create event
            event = {
                "timestamp": time.time(),
                "event": event_type,
                "path": str(path),
                "suspicious": path.suffix.lower() in [
                    ".encrypted", ".locked", ".crypto"
                ]
            }

            # Trackers
            self.extractor.add_event(event)
            self.session.add_event(event)

            # Features
            features = self.extractor.extract(path, entropy)
            stats = self.session.get_stats()

            # Risk
            risk, reasons = calculate_risk(features)
            severity = get_severity(risk)
            is_attack = is_ransomware(risk, features)

            # Timeline
            timeline_entry = f"{time.strftime('%H:%M:%S')} → {event_type} → {path.name}"

            # TERMINAL PRINT
            print(f"File: {path} | Entropy: {entropy:.2f} | [{severity}] Risk: {risk}")
            if reasons:
                print("Reasons:", ", ".join(reasons))

            # STRUCTURED LOG FOR UI (FIXED)
            log_entry = {
                "type": "event",
                "file": str(path),
                "entropy": entropy,
                "risk": risk,
                "severity": severity,
                "event_rate": features.get("event_rate"),
                "reasons": reasons,
                "timestamp": time.time(),
                "timeline": timeline_entry
            }

            add_log(log_entry)
            log_event(log_entry)

            # RESPONSE
            current_time = time.time()

            if is_attack:
                if current_time - self.last_alert > 5:
                    self.last_alert = current_time

                    print("[ACTION] RANSOMWARE detected → Quarantine triggered")

                    success, location = quarantine_file(path)

                    if success:
                        timeline_entry += " → ransomware detected → quarantined"
                    else:
                        timeline_entry += " → ransomware detected → quarantine failed"

                    alert = {
                        "type": "ransomware",
                        "severity": severity,
                        "risk": risk,
                        "file": str(path),
                        "event_rate": features.get("event_rate"),
                        "stats": stats,
                        "quarantined": success,
                        "location": location,
                        "timestamp": current_time,
                        "timeline": timeline_entry,
                        "reasons": reasons
                    }

                    add_log(alert)
                    log_event(alert)

            elif severity == "MEDIUM":
                timeline_entry += " → MEDIUM detected"

                warning = {
                    "type": "warning",
                    "severity": severity,
                    "risk": risk,
                    "file": str(path),
                    "event_rate": features.get("event_rate"),
                    "timestamp": current_time,
                    "timeline": timeline_entry,
                    "reasons": reasons
                }

                add_log(warning)
                log_event(warning)

        except Exception as e:
            error_msg = f"Error processing file: {e}"
            print(error_msg)
            add_log({"type": "error", "message": error_msg})


    def on_created(self, event):
        if not event.is_directory:
            print("DEBUG: created event", event.src_path)
            self.process(Path(str(event.src_path)), "created")

    def on_modified(self, event):
        if not event.is_directory:
            print("DEBUG: modified event", event.src_path)
            self.process(Path(str(event.src_path)), "modified")

    def on_moved(self, event):
        if not event.is_directory:
            print("DEBUG: moved event", event.dest_path)
            self.process(Path(str(event.dest_path)), "moved")


def start_monitor(folder):
    folder_path = Path(folder)
    folder_path.mkdir(parents=True, exist_ok=True)

    observer = Observer()
    handler = Handler()

    observer.schedule(handler, str(folder_path), recursive=True)
    observer.start()

    print("DEBUG: monitor started")
    print(f"Monitoring folder: {folder_path}")

    add_log({
        "type": "system",
        "message": f"Monitoring started on folder: {folder_path}",
        "timestamp": time.time()
    })

    return observer