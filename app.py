from flask import Flask, render_template, jsonify
import json
from logger import LOG_FILE
from controller import start_system, stop_system
from simulator_safe import simulate_attack
from live_log import get_logs

app = Flask(__name__, template_folder="templates")



def load_logs():
    if not LOG_FILE.exists():
        return []
    try:
        return json.loads(LOG_FILE.read_text())
    except Exception as exc:
        print("DEBUG: failed to load logs.json", exc)
        return []


def generate_report(logs):
    """Generate incident analytics report from logs"""
    report = {
        "total_events": len([l for l in logs if l.get("type") == "event"]),
        "total_alerts": len([l for l in logs if l.get("type") in ["warning", "ransomware"]]),
        "high_severity_count": len([l for l in logs if l.get("severity") == "HIGH 🚨"]),
        "medium_severity_count": len([l for l in logs if l.get("severity") == "MEDIUM"]),
        "quarantined_count": len([l for l in logs if l.get("quarantined") is True]),
        "last_attacked_file": None
    }
    report["quarantine_success_rate"] = (
        report["quarantined_count"] / report["high_severity_count"]
        if report["high_severity_count"] > 0 else 0
    )
    
    # Find last attacked file (ransomware detection)
    detections = [l for l in logs if l.get("type") == "ransomware"]
    if detections:
        report["last_attacked_file"] = detections[-1].get("file")
    
    return report


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/start")
def start():
    print("DEBUG: /start called")
    return jsonify({"status": start_system()})


@app.route("/stop")
def stop():
    print("DEBUG: /stop called")
    return jsonify({"status": stop_system()})


@app.route("/simulate")
def simulate():
    print("DEBUG: /simulate called")
    simulate_attack()
    return jsonify({"status": "Simulation started"})


@app.route("/logs")
def logs():
    return jsonify(load_logs())


@app.route("/live")
def live():
    return jsonify(get_logs())


@app.route("/report")
def report():
    logs = load_logs()
    analytics = generate_report(logs)
    detections = [l for l in logs if l.get("type") == "ransomware"]

    if not detections:
        return jsonify({
            "message": "No incidents detected",
            "analytics": analytics
        })

    latest = detections[-1]

    return jsonify({
        "type": latest.get("type"),
        "severity": latest.get("severity"),
        "file": latest.get("file"),
        "risk": latest.get("risk"),
        "files_affected": latest.get("stats", {}).get("file_count"),
        "rename_count": latest.get("stats", {}).get("rename_count"),
        "quarantined": latest.get("quarantined"),
        "location": latest.get("location"),
        "timestamp": latest.get("timestamp"),
        "analytics": analytics
    })
    
        
    


if __name__ == "__main__":
    app.run(debug=True, threaded=True)