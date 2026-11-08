import pandas as pd
from src.log_parser import load_logs
from src.risk_scoring import process_alerts


def detect_threats(logs):

    alerts = []

    # Rule 1: Detect repeated failed login attempts
    for (user, ip), group in logs.groupby(
        ["user_id", "ip_address"]
    ):

        failed = group[
            group["status"] == "FAILED"
        ].sort_values("timestamp")

        times = failed["timestamp"].tolist()

        for i in range(len(times)):
            window = [
                t for t in times
                if times[i] <= t <= times[i] + pd.Timedelta(minutes=5)
            ]

            if len(window) >= 5:
                alerts.append({
                    "Threat": "Brute Force Attack",
                    "User": user,
                    "IP Address": ip,
                    "Severity": "HIGH",
                    "Details": "5 or more failed logins within 5 minutes"
                })
                break

    # Rule 2: Detect one IP targeting multiple accounts
    failed_logs = logs[
        logs["status"] == "FAILED"
    ]

    for ip, group in failed_logs.groupby("ip_address"):

        users = group["user_id"].nunique()

        if users >= 5:
            alerts.append({
                "Threat": "Password Spraying",
                "User": "Multiple Accounts",
                "IP Address": ip,
                "Severity": "HIGH",
                "Details": f"One IP targeted {users} different accounts"
            })

    # Rule 3: Successful login after repeated failures
    for (user, ip), group in logs.groupby(
        ["user_id", "ip_address"]
    ):

        group = group.sort_values("timestamp")

        for _, row in group[
            group["status"] == "SUCCESS"
        ].iterrows():

            previous_failures = group[
                (group["status"] == "FAILED") &
                (group["timestamp"] < row["timestamp"]) &
                (group["timestamp"] >=
                 row["timestamp"] - pd.Timedelta(minutes=10))
            ]

            if len(previous_failures) >= 3:
                alerts.append({
                    "Threat": "Suspicious Successful Login",
                    "User": user,
                    "IP Address": ip,
                    "Severity": "CRITICAL",
                    "Details": "Successful login after 3 or more failures"
                })
                break

    # Rule 4: Detect high-volume failed login attempts
    for ip, group in failed_logs.groupby("ip_address"):

        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()

        for i in range(len(times)):
            count = sum(
                times[i] <= t <= times[i] + pd.Timedelta(minutes=10)
                for t in times
            )

            if count >= 8:
                alerts.append({
                    "Threat": "High Volume Failed Logins",
                    "User": "Multiple Accounts",
                    "IP Address": ip,
                    "Severity": "HIGH",
                    "Details": "8 or more failed logins within 10 minutes"
                })
                break

    return alerts


# Execute threat detection
if __name__ == "__main__":

    logs = load_logs("data/sample_auth_logs.csv")

    # Detect security threats
    alerts = detect_threats(logs)

    # Calculate risk scores
    scored_alerts = process_alerts(alerts)

    print("\nSOC SENTINEL - SECURITY ALERT REPORT")
    print("=" * 45)

    for i, alert in enumerate(scored_alerts, start=1):

        print(f"\nALERT {i}")
        print("-" * 35)

        for key, value in alert.items():
            print(f"{key}: {value}")

    print("\nTotal security alerts:", len(scored_alerts))
    print("Risk scoring completed successfully!")