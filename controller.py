import threading
from pathlib import Path
from monitor import start_monitor

BASE_DIR = Path(__file__).resolve().parent
observer_instance = None
monitor_thread = None

def start_system():
    global observer_instance, monitor_thread

    if observer_instance:
        print("DEBUG: monitor already running")
        return "Already running"

    folder = BASE_DIR / "sandbox"
    folder.mkdir(parents=True, exist_ok=True)

    print(f"DEBUG: starting monitor thread for folder: {folder}")

    def run():
        global observer_instance
        try:
            observer_instance = start_monitor(folder)
            print("DEBUG: monitor observer instance created")
        except Exception as exc:
            print("DEBUG: monitor failed to start:", exc)

    monitor_thread = threading.Thread(target=run, daemon=True)
    monitor_thread.start()

    return "Monitoring started"


def stop_system():
    global observer_instance

    if observer_instance:
        print("DEBUG: stopping monitor")
        observer_instance.stop()
        observer_instance.join(timeout=5)
        observer_instance = None
        return "Monitoring stopped"

    return "Not running"