def calculate_risk_score(alert):

    threat = alert["Threat"]

    risk_scores = {
        "Brute Force Attack": 75,
        "Password Spraying": 80,
        "Suspicious Successful Login": 95,
        "High Volume Failed Logins": 85
    }

    score = risk_scores.get(threat, 30)

    if score >= 90:
        risk_level = "CRITICAL"

    elif score >= 70:
        risk_level = "HIGH"

    elif score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    alert["Risk Score"] = score
    alert["Risk Level"] = risk_level

    return alert


def process_alerts(alerts):

    processed_alerts = []

    for alert in alerts:

        updated_alert = calculate_risk_score(
            alert.copy()
        )

        processed_alerts.append(updated_alert)

    return processed_alerts


if __name__ == "__main__":

    sample_alert = {
        "Threat": "Brute Force Attack",
        "User": "user05",
        "IP Address": "203.0.113.50",
        "Severity": "HIGH",
        "Details": "Repeated failed login attempts"
    }

    result = calculate_risk_score(sample_alert)

    print("\nSOC SENTINEL - RISK SCORING")
    print("=" * 35)

    for key, value in result.items():
        print(f"{key}: {value}")