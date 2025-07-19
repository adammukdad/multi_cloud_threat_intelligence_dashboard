import streamlit as st
import json
import os

st.set_page_config(page_title="Multi-Cloud Threat Intelligence Dashboard", layout="wide")

st.title("☁️ Multi-Cloud Threat Intelligence Dashboard")
st.markdown("Shows normalized security alerts from AWS, Azure, and cross-cloud correlation.")

# Load alert files
def load_alerts(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return []

aws_alerts = load_alerts("aws/aws_alerts_parsed.json")
azure_alerts = load_alerts("azure/azure_alerts_parsed.json")
correlated_alerts = load_alerts("correlation_engine/correlated_alerts.json")

# --- Sidebar Filter ---
severity_filter = st.sidebar.selectbox("Filter by Severity", ["All", "High", "Medium", "Critical"])
cloud_filter = st.sidebar.multiselect("Cloud Source", ["AWS", "Azure"], default=["AWS", "Azure"])

def filter_alerts(alerts):
    return [
        alert for alert in alerts
        if (severity_filter == "All" or alert["severity"] == severity_filter)
        and (alert["cloud"] in cloud_filter if "cloud" in alert else True)
    ]

# --- Section: AWS Alerts ---
st.subheader("🟨 AWS Alerts")
for alert in filter_alerts(aws_alerts):
    ip = alert.get("sourceIP", "N/A")
    with st.expander(f"[{alert['severity']}] {alert['eventType']} from {ip}"):
        st.json(alert)

# --- Section: Azure Alerts ---
st.subheader("🟦 Azure Alerts")
for alert in filter_alerts(azure_alerts):
    ip = alert.get("sourceIP", "N/A")
    with st.expander(f"[{alert['severity']}] {alert['eventType']} from {ip}"):
        st.json(alert)

# --- Section: Correlated Alerts ---
st.subheader("🔁 Correlated Cross-Cloud Alerts")
for alert in correlated_alerts:
    ip = alert.get("sourceIP", "N/A")
    event_types = ", ".join(alert.get("eventTypes", []))
    with st.expander(f"[{alert['severity']}] IP {ip} | {event_types}"):
        st.json(alert)