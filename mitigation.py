import shutil
from pathlib import Path
from datetime import datetime
from logger import log_event as log_json_event  

QUARANTINE_DIR = Path("quarantine")


# ✅ Terminal logger (different name)
def log_terminal(event, file):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} → {event} → {file}")


def quarantine_file(file_path):
    try:
        QUARANTINE_DIR.mkdir(exist_ok=True)

        src = Path(file_path)
        dest = QUARANTINE_DIR / src.name

        if src.exists():
            shutil.move(str(src), str(dest))

            # 🔥 Terminal log
            log_terminal("THREAT_CONTAINED → FILE_QUARANTINED", dest)

            # 🔥 JSON log (correct function)
            log_json_event({
                "type": "mitigation",
                "action": "quarantine",
                "file": str(dest),
                "status": "success"
            })

            return True, str(dest)

        else:
            log_terminal("FILE_NOT_FOUND", file_path)

            log_json_event({
                "type": "mitigation",
                "action": "quarantine",
                "file": str(file_path),
                "status": "failed"
            })

            return False, "file not found"

    except Exception as e:
        log_terminal("ERROR_QUARANTINE_FAILED", file_path)

        log_json_event({
            "type": "mitigation",
            "action": "quarantine",
            "file": str(file_path),
            "status": "error",
            "error": str(e)
        })

        return False, str(e)