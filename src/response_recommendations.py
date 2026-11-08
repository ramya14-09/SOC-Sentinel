
def get_recommendation(threat):

    recommendations = {

        "Brute Force Attack": {
            "Action": "Temporarily block the suspicious IP address.",
            "Priority": "HIGH",
            "Steps": [
                "Review repeated failed login attempts.",
                "Temporarily block the suspicious IP.",
                "Enable account lockout policies.",
                "Ask the affected user to reset their password."
            ]
        },

        "Password Spraying": {
            "Action": "Investigate the source IP and targeted accounts.",
            "Priority": "HIGH",
            "Steps": [
                "Identify all targeted user accounts.",
                "Investigate the suspicious source IP.",
                "Apply rate limiting to login requests.",
                "Enable multi-factor authentication."
            ]
        },

        "Suspicious Successful Login": {
            "Action": "Verify whether the successful login was legitimate.",
            "Priority": "CRITICAL",
            "Steps": [
                "Contact the affected account owner.",
                "Review the login time and source IP.",
                "Reset credentials if compromise is suspected.",
                "Revoke suspicious active sessions."
            ]
        },

        "High Volume Failed Logins": {
            "Action": "Investigate the source of repeated failed logins.",
            "Priority": "HIGH",
            "Steps": [
                "Identify the source IP address.",
                "Review the affected user accounts.",
                "Apply temporary rate limiting.",
                "Monitor for additional suspicious activity."
            ]
        }
    }

    return recommendations.get(
        threat,
        {
            "Action": "Perform manual security investigation.",
            "Priority": "MEDIUM",
            "Steps": [
                "Review the associated login records.",
                "Investigate the source IP.",
                "Monitor for further suspicious activity."
            ]
        }
    )
