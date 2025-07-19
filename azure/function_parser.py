import json
from collections import defaultdict

# Load the AAD sign-in logs
with open("aad_signin_logs.json", "r") as f:
    logs = json.load(f)

failed_attempts_by_ip = defaultdict(list)
alerts = []

# Process each sign-in event
for entry in logs:
    ip = entry.get("ipAddress")
    user = entry.get("userPrincipalName")
    timestamp = entry.get("createdDateTime")
    city = entry.get("location", {}).get("city", "Unknown")
    country = entry.get("location", {}).get("countryOrRegion", "Unknown")
    risk_level = entry.get("riskLevelDuringSignIn", "none")
    risk_state = entry.get("riskState", "none")
    failure_reason = entry.get("status", {}).get("failureReason", "Unknown")

    failed_attempts_by_ip[ip].append({
        "timestamp": timestamp,
        "user": user,
        "risk": risk_level,
        "riskState": risk_state,
        "reason": failure_reason
    })

# Normalize alerts
for ip, attempts in failed_attempts_by_ip.items():
    total_attempts = len(attempts)
    risk_levels = [a["risk"] for a in attempts]
    high_risk = any(r == "high" for r in risk_levels)

    alerts.append({
        "cloud": "Azure",
        "eventType": "AnomalousLogin",
        "sourceIP": ip,
        "userTargeted": attempts[0]["user"],
        "failedAttempts": total_attempts,
        "riskLevels": risk_levels,
        "riskState": attempts[-1]["riskState"],
        "geo": f"{attempts[0]['reason']} | {city}, {country}",
        "timestamps": [a["timestamp"] for a in attempts],
        "severity": "High" if high_risk or total_attempts >= 3 else "Medium"
    })

# Save to file
with open("azure_alerts_parsed.json", "w") as f:
    json.dump(alerts, f, indent=2)

print("Parsed output saved to azure_alerts_parsed.json")
