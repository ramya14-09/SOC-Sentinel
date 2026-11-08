
import pandas as pd
from src.detection_engine import detect_threats


def test_brute_force_detection():
    logs = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-11-08 10:00:00",
            "2026-11-08 10:01:00",
            "2026-11-08 10:02:00",
            "2026-11-08 10:03:00",
            "2026-11-08 10:04:00"
        ]),
        "user_id": ["ramya"] * 5,
        "ip_address": ["192.0.2.10"] * 5,
        "event_type": ["LOGIN"] * 5,
        "status": ["FAILED"] * 5
    })

    alerts = detect_threats(logs)

    assert any(
        alert["Threat"] == "Brute Force Attack"
        for alert in alerts
    )


def test_no_threat_for_single_failed_login():
    logs = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-11-08 10:00:00"]),
        "user_id": ["ramya"],
        "ip_address": ["192.0.2.10"],
        "event_type": ["LOGIN"],
        "status": ["FAILED"]
    })

    alerts = detect_threats(logs)

    assert not any(
        alert["Threat"] == "Brute Force Attack"
        for alert in alerts
    )

def test_password_spraying_detection():
    logs = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-11-08 10:00:00",
            "2026-11-08 10:01:00",
            "2026-11-08 10:02:00",
            "2026-11-08 10:03:00",
            "2026-11-08 10:04:00"
        ]),
        "user_id": ["user1", "user2", "user3", "user4", "user5"],
        "ip_address": ["192.0.2.20"] * 5,
        "event_type": ["LOGIN"] * 5,
        "status": ["FAILED"] * 5
    })

    alerts = detect_threats(logs)

    assert any(
        alert["Threat"] == "Password Spraying"
        for alert in alerts
    )


def test_suspicious_successful_login_detection():
    logs = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-11-08 10:00:00",
            "2026-11-08 10:01:00",
            "2026-11-08 10:02:00",
            "2026-11-08 10:03:00"
        ]),
        "user_id": ["ramya"] * 4,
        "ip_address": ["192.0.2.30"] * 4,
        "event_type": ["LOGIN"] * 4,
        "status": ["FAILED", "FAILED", "FAILED", "SUCCESS"]
    })

    alerts = detect_threats(logs)

    assert any(
        alert["Threat"] == "Suspicious Successful Login"
        for alert in alerts
    )

from src.risk_scoring import process_alerts


def test_risk_scoring():
    alerts = [
        {
            "Threat": "Brute Force Attack",
            "User": "ramya",
            "IP Address": "192.0.2.10",
            "Severity": "High",
            "Details": "Multiple failed login attempts"
        },
        {
            "Threat": "Suspicious Successful Login",
            "User": "admin",
            "IP Address": "192.0.2.20",
            "Severity": "Critical",
            "Details": "Successful login after repeated failures"
        }
    ]

    result = process_alerts(alerts)

    assert result[0]["Risk Score"] == 75
    assert result[0]["Risk Level"] == "HIGH"

    assert result[1]["Risk Score"] == 95
    assert result[1]["Risk Level"] == "CRITICAL"
