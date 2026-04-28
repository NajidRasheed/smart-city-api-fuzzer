# fuzz_dashboard.py - Upgraded Streamlit dashboard with severity detection

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import requests

BASE_URL = "http://127.0.0.1:5000"

payloads = [
    ("/api/login",    "POST", {"username": "A" * 10000, "password": "test"},          "Buffer Overflow"),
    ("/api/login",    "POST", {"username": "!@#$%^&*()", "password": "test"},          "Special Characters"),
    ("/api/login",    "POST", {"username": "' OR 1=1 --", "password": "test"},         "SQL Injection"),
    ("/api/login",    "POST", {"username": 12345, "password": "test"},                 "Type Mismatch"),
    ("/api/login",    "POST", {"username": None, "password": "test"},                  "Null Value"),
    ("/api/login",    "POST", {"username": "", "password": ""},                        "Empty String"),
    ("/api/login",    "POST", {"username": "   ", "password": "   "},                  "Whitespace Only"),
    ("/api/search",   "GET",  {"q": "こんにちは"},                                      "Unicode Input"),
    ("/api/search",   "GET",  {"q": "🚀🔥💻"},                                           "Emoji Input"),
    ("/api/login",    "POST", {"username": {"nested": "object"}, "password": "test"},  "Nested JSON"),
    ("/api/login",    "POST", {"username": 999999999999999999999, "password": "test"}, "Huge Number"),
    ("/api/search",   "GET",  {"q": "<script>alert('XSS')</script>"},                  "XSS Attempt"),
    ("/api/search",   "GET",  {"q": "../../etc/passwd"},                               "Path Traversal"),
    ("/api/transfer", "POST", {"amount": -99999},                                      "Negative Amount"),
    ("/api/transfer", "POST", {"date": "2026-99-99"},                                  "Malformed Date"),
    ("/api/login",    "POST", {"username": "abc123", "password": "test"},              "Wrong ID Type"),
]

def assess_severity(status, response_text):
    critical_keywords = ["sql", "syntax error", "select *", "query", "db error"]
    high_keywords = ["script", "xss", "reflected", "passwd", "path", "overflow", "buffer", "stack"]
    medium_keywords = ["null", "none", "typeerror", "exception", "invalid", "dateparse"]
    text_lower = response_text.lower()
    if status >= 500:
        if any(k in text_lower for k in critical_keywords):
            return "CRITICAL"
        if any(k in text_lower for k in high_keywords):
            return "HIGH"
        return "MEDIUM"
    if status >= 400:
        if any(k in text_lower for k in medium_keywords):
            return "MEDIUM"
        return "LOW"
    if status == 200:
        if any(k in text_lower for k in high_keywords):
            return "HIGH"
        return "INFO"
    return "INFO"

SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "🟢"}

def run_fuzz_tests():
    results = []
    for i, (endpoint, method, payload, label) in enumerate(payloads, start=1):
        try:
            url = BASE_URL + endpoint
            if method == "POST":
                response = requests.post(url, json=payload, timeout=5)
            else:
                response = requests.get(url, params=payload, timeout=5)
            status = response.status_code
            severity = assess_severity(status, response.text)
            category = (
                "Success" if 200 <= status < 300 else
                "Client Error" if 400 <= status < 500 else
                "Server Error" if 500 <= status < 600 else "Other"
            )
            results.append({
                "Test #": i,
                "Label": label,
                "Endpoint": f"{method} {endpoint}",
                "Status": status,
                "Category": category,
                "Severity": f"{SEVERITY_EMOJI[severity]} {severity}",
                "Response": response.text[:150]
            })
        except Exception as e:
            results.append({
                "Test #": i,
                "Label": label,
                "Endpoint": f"{method} {endpoint}",
                "Status": "ERR",
                "Category": "Other",
                "Severity": "⚪ UNKNOWN",
                "Response": str(e)
            })
    return pd.DataFrame(results)

# --- Streamlit UI ---
st.set_page_config(page_title="API Fuzzer", page_icon="🔍", layout="wide")
st.title("🔍 API Fuzz Testing Dashboard")
st.caption("Final Year Project — Automated API Vulnerability Detection")

col1, col2 = st.columns([2, 1])
with col1:
    st.info("Make sure `vulnerable_server.py` is running on port 5000 before clicking Run.")
with col2:
    run = st.button("▶ Run Fuzz Tests", use_container_width=True)

if run:
    with st.spinner("Running fuzz tests..."):
        df = run_fuzz_tests()

    # Metrics
    total = len(df)
    critical = len(df[df["Severity"].str.contains("CRITICAL")])
    high = len(df[df["Severity"].str.contains("HIGH")])
    server_errors = len(df[df["Category"] == "Server Error"])

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Tests", total)
    m2.metric("🔴 Critical", critical)
    m3.metric("🟠 High Risk", high)
    m4.metric("💥 Server Crashes", server_errors)

    st.subheader("📋 Results Table")
    st.dataframe(df, use_container_width=True)

    st.subheader("📊 Charts")
    c1, c2 = st.columns(2)

    with c1:
        counts = df["Category"].value_counts()
        fig, ax = plt.subplots()
        counts.plot(kind="bar", color=["#4CAF50", "#F44336", "#FF9800", "#9E9E9E"], ax=ax)
        ax.set_title("Response Status Distribution")
        ax.set_ylabel("Count")
        plt.xticks(rotation=30)
        st.pyplot(fig)

    with c2:
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev_counts = df["Severity"].str.extract(r'([A-Z]+)')[0].value_counts().reindex(sev_order, fill_value=0)
        fig2, ax2 = plt.subplots()
        sev_counts.plot(kind="bar", color=["#B71C1C", "#F44336", "#FF9800", "#FFC107", "#4CAF50"], ax=ax2)
        ax2.set_title("Vulnerability Severity Breakdown")
        ax2.set_ylabel("Count")
        plt.xticks(rotation=30)
        st.pyplot(fig2)

    st.subheader("🔍 Detailed Findings")
    for _, row in df.iterrows():
        with st.expander(f"Test {row['Test #']} — {row['Label']} — {row['Severity']}"):
            st.code(f"Endpoint : {row['Endpoint']}\nStatus   : {row['Status']}\nSeverity : {row['Severity']}\nResponse : {row['Response']}")