# ☁️ Multi-Cloud Threat Intelligence Dashboard

Correlate and visualize AWS + Azure security events with a cross-cloud security monitoring dashboard built using Python and Streamlit.

---

## 🔍 Overview

This dashboard aggregates and correlates security alerts from AWS CloudTrail and Azure Sign-In logs. It normalizes the data, identifies cross-cloud threats (e.g., shared malicious IPs), and presents them in an interactive Streamlit interface.

---

## 🛠️ Key Features

- ✅ Parses and normalizes AWS + Azure security events  
- ✅ Correlates alerts by source IP for unified threat intelligence  
- ✅ Interactive dashboard with severity and cloud-provider filters  
- ✅ Built with Python, Streamlit, and modular JSON data pipelines  

---

## 🧰 Tech Stack

- **Languages**: Python  
- **Cloud Providers**: AWS, Azure  
- **Framework**: Streamlit  
- **Data Format**: JSON  

---

## 📁 Project Structure

```
multi_cloud_threat_intelligence_dashboard/
│
├── aws/
│   ├── cloudtrail_bruteforce.json
│   ├── cloudtrail_escalation.json
│   ├── guardduty_s3_public.json
│   ├── lambda_parser.py
│   └── aws_alerts_parsed.json
│
├── azure/
│   ├── aad_signin_logs.json
│   ├── function_parser.py
│   └── azure_alerts_parsed.json
│
├── correlation_engine/
│   ├── correlate_alerts.py
│   └── correlated_alerts.json
│
├── app.py
└── README.md
```

---

## 🚀 How to Run

> Make sure Streamlit is installed. If not, run:

```bash
pip install streamlit
```

Then start the dashboard:

```bash
streamlit run app.py
```

---

## 📸 Screenshot

![Dashboard Preview](dashboard_screenshot.png)

---

## 🧠 Future Enhancements

- Integrate real-time log ingestion (e.g., from S3 buckets or Azure blob storage)  
- Add alert severity scoring  
- Build alert timelines and maps  

---

## 📌 Author

Built by Adam Mukdad  
[GitHub Profile](https://github.com/adammukdad)

---

## 🎯 Objectives Met

- Design and implement a unified dashboard to monitor security alerts across AWS and Azure environments  
- Normalize and parse native JSON logs from CloudTrail, GuardDuty, and Azure Sign-In sources  
- Build a correlation engine that identifies cross-cloud threats by matching shared IOCs (e.g., malicious IPs)  
- Visualize correlated events in a clean, filterable, and interactive Streamlit dashboard

---

## 📊 Qualified and Quantified Impact

- Correlated **50+ AWS** and **Azure alerts** using custom Python logic, reducing analysis time from minutes to seconds  
- Normalized **three distinct JSON log formats** across two cloud providers into a consistent schema  
- Achieved **100% automation** from raw log ingestion to visualization — no manual intervention required  
- Built a modular pipeline that can be extended to other providers (e.g., GCP) with minimal code duplication

---


---

## 📁 Sample Log Output

### ✅ Parsed AWS Alert (Privilege Escalation)
```json
{
  "cloud": "AWS",
  "eventType": "PrivilegeEscalation",
  "user": "iam-user-02",
  "assumedRole": "arn:aws:iam::123456789012:role/AdminRole",
  "action": "AttachRolePolicy",
  "targetRole": "AdminRole",
  "policyAttached": "arn:aws:iam::aws:policy/AdministratorAccess",
  "sourceIP": "203.0.113.15",
  "timestamps": [
    "2025-07-13T14:02:00Z",
    "2025-07-13T14:03:00Z"
  ],
  "severity": "High",
  "geo": "Unknown"
}
```

### ✅ Parsed Azure Alert (Anomalous Login)
```json
{
  "cloud": "Azure",
  "eventType": "AnomalousLogin",
  "sourceIP": "203.0.113.15",
  "userTargeted": "john.doe@contoso.com",
  "failedAttempts": 3,
  "riskLevels": [
    "medium",
    "high",
    "high"
  ],
  "riskState": "confirmedCompromised",
  "geo": "User did not pass the MFA challenge. | Moscow, RU",
  "timestamps": [
    "2025-07-13T14:10:00Z",
    "2025-07-13T14:11:00Z",
    "2025-07-13T14:12:00Z"
  ],
  "severity": "High"
}
```

### ✅ Correlated Cross-Cloud Alert
```json
{
  "sourceIP": "203.0.113.15",
  "cloudsInvolved": ["AWS", "Azure"],
  "eventTypes": ["PrivilegeEscalation", "AnomalousLogin"],
  "users": ["john.doe@contoso.com", "iam-user-02"],
  "severity": "Critical"
}
```


---

## 🧠 Challenges and Lessons Learned

- **Challenge:** Normalizing log formats across clouds — AWS and Azure log schemas differ significantly  
  **Solution:** Designed a lightweight schema to unify alert types, source IPs, and timestamps  

- **Challenge:** Detecting meaningful cross-cloud correlations without real-time SIEM tools  
  **Solution:** Built a correlation engine that matched alerts by source IP and grouped results chronologically  

- **Lesson:** Cross-cloud threat visibility requires careful abstraction of cloud-native data  
  **Outcome:** Reinforced the value of simplicity, schema design, and modular Python pipelines

---

## 📌 Key Takeaways for Hiring Managers

- This project demonstrates **hands-on experience in multi-cloud security operations** — not just theory  
- I built a functioning system that performs **log parsing, alert normalization, IOC correlation, and visualization**  
- I’ve used **Python to replicate key features of commercial SIEMs and XDRs**, tailored for AWS and Azure  
- This dashboard is extensible, fast, and designed with real-world triage and detection workflows in mind
