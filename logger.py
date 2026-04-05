import json
import time
from pathlib import Path

LOG_FILE = Path("logs.json")

def log_event(data):
    if not LOG_FILE.exists():
        LOG_FILE.write_text("[]")

    try:
        logs = json.loads(LOG_FILE.read_text())
    except:
        logs = []

    data["logged_at"] = time.time()
    logs.append(data)

    LOG_FILE.write_text(json.dumps(logs, indent=2))