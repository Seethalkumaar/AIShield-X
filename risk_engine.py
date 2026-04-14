from config import *

def calculate_risk(features):
    risk = 0
    reasons = []

    # Entropy
    if features["entropy"] > ENTROPY_THRESHOLD:
        risk += 30
        reasons.append("+30 High entropy (possible encryption)")

    # Suspicious extension
    if features["suspicious_ext"]:
        risk += 10
        reasons.append("+10 Suspicious file extension (.encrypted/.locked)")

    # Event rate
    if features["event_rate"] > EVENT_RATE_THRESHOLD:
        risk += 25
        reasons.append("+25 Rapid file activity")

    # Rename count
    if features["rename_count"] > RENAME_THRESHOLD:
        risk += 20
        reasons.append("+20 Multiple file renames")

    return risk, reasons


def explain_risk(features):
    risk, reasons = calculate_risk(features)
    return reasons


def is_ransomware(risk, features=None):
    threshold = RISK_THRESHOLD
    if features and isinstance(features, dict):
        event_rate = features.get("event_rate")
        if isinstance(event_rate, (int, float)) and event_rate > EVENT_RATE_THRESHOLD:
            threshold = RISK_THRESHOLD - 10
    return risk >= threshold


def get_severity(risk):
    if risk < 30:
        return "LOW"
    elif risk < 60:
        return "MEDIUM"
    else:
        return "HIGH"