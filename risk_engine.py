from config import *

def calculate_risk(features):
    risk = 0

    if features["entropy"] > ENTROPY_THRESHOLD:
        risk += 30

    if features["suspicious_ext"]:
        risk += 10

    if features["event_rate"] > EVENT_RATE_THRESHOLD:
        risk += 25

    if features["rename_count"] > RENAME_THRESHOLD:
        risk += 20

    return risk


def is_ransomware(risk):
    return risk >= RISK_THRESHOLD


def get_severity(risk):
    if risk < 30:
        return "LOW"
    elif risk < 60:
        return "MEDIUM"
    else:
        return "HIGH 🚨"