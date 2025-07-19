import json

# Load parsed alerts
with open("../aws/aws_alerts_parsed.json", "r") as f1, open("../azure/azure_alerts_parsed.json", "r") as f2:
    aws_alerts = json.load(f1)
    azure_alerts = json.load(f2)

correlated_alerts = []
ip_index = {}

# Index alerts by IP
for alert in aws_alerts + azure_alerts:
    ip = alert.get("sourceIP", "")
    if ip not in ip_index:
        ip_index[ip] = []
    ip_index[ip].append(alert)

# Correlate alerts by source IP
for ip, group in ip_index.items():
    if len(group) > 1:
        correlated_alerts.append({
            "correlationID": f"correl_{ip.replace('.', '-')}",
            "sourceIP": ip,
            "cloudsInvolved": list(set(a["cloud"] for a in group)),
            "eventTypes": [a["eventType"] for a in group],
            "users": list(set(a.get("userTargeted", a.get("user", "Unknown")) for a in group)),
            "severity": "Critical" if any(a["severity"] == "High" for a in group) else "Medium",
            "events": group
        })

# Save final output
with open("correlated_alerts.json", "w") as f:
    json.dump(correlated_alerts, f, indent=2)

print("Correlated alerts saved to correlated_alerts.json")
