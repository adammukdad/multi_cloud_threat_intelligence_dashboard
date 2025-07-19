import json
from collections import defaultdict

# --- LOAD LOG FILES ---
with open("cloudtrail_bruteforce.json", "r") as f1, \
     open("cloudtrail_escalation.json", "r") as f2, \
     open("guardduty_s3_public.json", "r") as f3:
    bruteforce_logs = json.load(f1)
    escalation_logs = json.load(f2)
    guardduty_logs = json.load(f3)

all_events = bruteforce_logs + escalation_logs
alerts = []

# --- BRUTE FORCE DETECTION ---
failed_attempts_by_ip = defaultdict(list)

for event in all_events:
    if (
        event.get("eventName") == "ConsoleLogin" and
        event.get("responseElements", {}).get("ConsoleLogin") == "Failure"
    ):
        ip = event.get("sourceIPAddress")
        user = event.get("userIdentity", {}).get("userName")
        timestamp = event.get("eventTime")
        failed_attempts_by_ip[ip].append({"timestamp": timestamp, "user": user})

for ip, attempts in failed_attempts_by_ip.items():
    alerts.append({
        "cloud": "AWS",
        "eventType": "BruteForceLogin",
        "sourceIP": ip,
        "userTargeted": attempts[0]["user"],
        "failedAttempts": len(attempts),
        "timestamps": [a["timestamp"] for a in attempts],
        "severity": "High" if len(attempts) >= 5 else "Medium",
        "geo": "Unknown"
    })

# --- PRIVILEGE ESCALATION DETECTION ---
assumed_roles = {}

for event in all_events:
    event_name = event.get("eventName")
    source_ip = event.get("sourceIPAddress")
    timestamp = event.get("eventTime")

    if event_name == "AssumeRole":
        user = event.get("userIdentity", {}).get("userName")
        role = event.get("requestParameters", {}).get("roleArn")
        session = event.get("requestParameters", {}).get("roleSessionName")
        assumed_roles[session] = {
            "sourceIP": source_ip,
            "timestamp": timestamp,
            "user": user,
            "role": role
        }

    if event_name == "AttachRolePolicy" and event.get("userIdentity", {}).get("type") == "AssumedRole":
        arn = event.get("userIdentity", {}).get("arn")
        session = arn.split("/")[-1]
        policy = event.get("requestParameters", {}).get("policyArn")
        role_name = event.get("requestParameters", {}).get("roleName")

        if session in assumed_roles:
            escalation = assumed_roles[session]
            alerts.append({
                "cloud": "AWS",
                "eventType": "PrivilegeEscalation",
                "user": escalation["user"],
                "assumedRole": escalation["role"],
                "action": "AttachRolePolicy",
                "targetRole": role_name,
                "policyAttached": policy,
                "sourceIP": escalation["sourceIP"],
                "timestamps": [escalation["timestamp"], timestamp],
                "severity": "High",
                "geo": "Unknown"
            })

# --- S3 PUBLIC EXPOSURE DETECTION ---
for finding in guardduty_logs:
    if finding.get("type") == "Policy:IAMUser/S3BucketPublicAccessGranted":
        bucket = finding.get("resource", {}).get("s3BucketDetails", [{}])[0].get("name", "Unknown")
        first_seen = finding.get("service", {}).get("eventFirstSeen")
        last_seen = finding.get("service", {}).get("eventLastSeen")

        alerts.append({
            "cloud": "AWS",
            "eventType": "S3PublicExposure",
            "bucketName": bucket,
            "detectionTime": [first_seen, last_seen],
            "severity": "High",
            "geo": "Unknown",
            "source": "GuardDuty"
        })

# --- SAVE OUTPUT ---
with open("aws_alerts_parsed.json", "w") as f:
    json.dump(alerts, f, indent=2)

print("Parsed output saved to aws_alerts_parsed.json")
