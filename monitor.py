import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from entropy import calculate_entropy
from features import FeatureExtractor
from risk_engine import calculate_risk, is_ransomware, get_severity
from logger import log_event
from session import SessionTracker
from mitigation import quarantine_file
from live_log import add_log


class Handler(FileSystemEventHandler):
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.session = SessionTracker()
        self.last_alert = 0

    def process(self, path, event_type):
        print("DEBUG: event received", event_type, path)

        if not path.exists() or not path.is_file():
            print("DEBUG: skipped non-file path", path)
            return

        try:
            # Read part of file safely
            data = path.read_bytes()[:200000]
            entropy = calculate_entropy(data)

            # Create event
            event = {
                "timestamp": time.time(),
                "event": event_type,
                "path": str(path),
                "suspicious": path.suffix.lower() in [
                    ".encrypted", ".locked", ".crypto"
                ]
            }

            # Add to trackers
            self.extractor.add_event(event)
            self.session.add_event(event)

            # Extract features
            features = self.extractor.extract(path, entropy)
            stats = self.session.get_stats()

            # Calculate risk
            risk = calculate_risk(features)
            severity = get_severity(risk)

            # 🧠 Timeline base
            timeline_entry = f"{time.strftime('%H:%M:%S')} → {event_type} → {path.name}"

            # 🔹 Terminal + UI log
            msg = f"File: {path} | Entropy: {entropy:.2f} | [{severity}] Risk: {risk}"
            print(msg)
            add_log(msg)

            # 📊 Log every event (for graph)
            event_log = {
                "type": "event",
                "file": str(path),
                "risk": risk,
                "severity": severity,
                "timestamp": time.time(),
                "timeline": timeline_entry
            }
            log_event(event_log)

            # 🔥 Severity-based response
            current_time = time.time()

            if severity == "HIGH 🚨":
                if current_time - self.last_alert > 5:
                    self.last_alert = current_time

                    print("[ACTION] HIGH → Quarantine triggered")
                    alert_msg = f"[ALERT] 🚨 RANSOMWARE → {path} (Risk: {risk})"
                    print(alert_msg)
                    add_log(alert_msg)

                    # 🛑 Mitigation
                    success, location = quarantine_file(path)

                    mitigation_info = {
                        "quarantined": success,
                        "location": location
                    }

                    # ✅ Timeline update (CORRECT)
                    if success:
                        timeline_entry = timeline_entry + " → HIGH detected → quarantined"
                    else:
                        timeline_entry = timeline_entry + " → HIGH detected → quarantine failed"

                    print("Mitigation:", mitigation_info)
                    add_log(f"Mitigation: {mitigation_info}")

                    # 📦 Final structured alert
                    alert = {
                        "type": "ransomware",
                        "severity": severity,
                        "risk": risk,
                        "file": str(path),
                        "stats": stats,
                        "quarantined": success,
                        "location": location,
                        "timestamp": current_time,
                        "timeline": timeline_entry
                    }

                    log_event(alert)

            elif severity == "MEDIUM":
                print("[ACTION] MEDIUM → Alert logged")

                timeline_entry = timeline_entry + " → MEDIUM detected"

                warning_log = {
                    "type": "warning",
                    "severity": severity,
                    "risk": risk,
                    "file": str(path),
                    "timestamp": current_time,
                    "timeline": timeline_entry
                }

                log_event(warning_log)

            elif severity == "LOW":
                print("[ACTION] LOW → Ignored")

        except Exception as e:
            error_msg = f"Error processing file: {e}"
            print(error_msg)
            add_log(error_msg)

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
    add_log(f"Monitoring started on folder: {folder_path}")

    return observer