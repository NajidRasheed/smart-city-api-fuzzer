# api_fuzzer.py - Upgraded with vulnerability detection and severity rating

import requests
import os
import datetime
import matplotlib.pyplot as plt

# Point to our local vulnerable server instead of jsonplaceholder
BASE_URL = "http://127.0.0.1:5000"

payloads = [
    # (endpoint, method, payload, label)
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

# Severity rules based on what we find in responses
def assess_severity(status, response_text, label):
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
            return "HIGH"  # e.g. XSS reflected in 200 response
        return "INFO"
    return "INFO"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_PATH = os.path.join(BASE_DIR, "..", "logs", "fuzz_results.txt")

def fuzz_api():
    summary = {"success": 0, "client_error": 0, "server_error": 0, "other": 0}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    with open(LOGS_PATH, "w", encoding="utf-8") as f:
        f.write("=== Fuzz Test Results ===\n\n")

    for i, (endpoint, method, payload, label) in enumerate(payloads, start=1):
        try:
            url = BASE_URL + endpoint
            start_time = datetime.datetime.now()

            if method == "POST":
                response = requests.post(url, json=payload, timeout=5)
            else:
                response = requests.get(url, params=payload, timeout=5)

            elapsed = (datetime.datetime.now() - start_time).total_seconds()
            status = response.status_code
            severity = assess_severity(status, response.text, label)

            if 200 <= status < 300:
                summary["success"] += 1
            elif 400 <= status < 500:
                summary["client_error"] += 1
            elif 500 <= status < 600:
                summary["server_error"] += 1
            else:
                summary["other"] += 1

            severity_counts[severity] += 1

            log_entry = (
                f"Test {i} [{label}] ({start_time})\n"
                f"  Endpoint : {method} {endpoint}\n"
                f"  Payload  : {str(payload)[:120]}\n"
                f"  Status   : {status}\n"
                f"  Severity : {severity}\n"
                f"  Time     : {elapsed:.3f}s\n"
                f"  Response : {response.text[:200]}\n"
                + "-" * 60 + "\n"
            )
            print(log_entry)

            with open(LOGS_PATH, "a", encoding="utf-8") as f:
                f.write(log_entry)

        except Exception as e:
            summary["other"] += 1
            error_entry = f"Test {i} [{label}]: Exception — {e}\n"
            print(error_entry)
            with open(LOGS_PATH, "a", encoding="utf-8") as f:
                f.write(error_entry)

    summary_entry = (
        "\n=== Summary ===\n"
        f"Success (2xx) : {summary['success']}\n"
        f"Client Errors : {summary['client_error']}\n"
        f"Server Errors : {summary['server_error']}\n"
        f"Other         : {summary['other']}\n"
        f"\n=== Severity Breakdown ===\n"
        f"CRITICAL : {severity_counts['CRITICAL']}\n"
        f"HIGH     : {severity_counts['HIGH']}\n"
        f"MEDIUM   : {severity_counts['MEDIUM']}\n"
        f"LOW      : {severity_counts['LOW']}\n"
        f"INFO     : {severity_counts['INFO']}\n"
    )
    print(summary_entry)
    with open(LOGS_PATH, "a", encoding="utf-8") as f:
        f.write(summary_entry)

    visualize_results(summary, severity_counts)

def visualize_results(summary, severity_counts):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Chart 1: Status code distribution
    categories = ["Success", "Client Errors", "Server Errors", "Other"]
    counts = [summary["success"], summary["client_error"], summary["server_error"], summary["other"]]
    colors = ["#4CAF50", "#FF9800", "#F44336", "#9E9E9E"]
    bars = ax1.bar(categories, counts, color=colors)
    for bar, count in zip(bars, counts):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height(), str(count), ha="center", va="bottom", fontsize=12)
    ax1.set_title("Response Status Distribution")
    ax1.set_ylabel("Number of Tests")

    # Chart 2: Severity distribution
    sev_labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_values = [severity_counts[s] for s in sev_labels]
    sev_colors = ["#B71C1C", "#F44336", "#FF9800", "#FFC107", "#4CAF50"]
    bars2 = ax2.bar(sev_labels, sev_values, color=sev_colors)
    for bar, count in zip(bars2, sev_values):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height(), str(count), ha="center", va="bottom", fontsize=12)
    ax2.set_title("Vulnerability Severity Breakdown")
    ax2.set_ylabel("Number of Findings")

    plt.tight_layout()
    plt.savefig(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "fuzz_chart.png"))
    plt.show()

if __name__ == "__main__":
    fuzz_api()