import requests
import os
import datetime
import matplotlib.pyplot as plt

API_URL = "https://jsonplaceholder.typicode.com/posts"

payloads = [
    {"data": "A" * 10000},
    {"data": "!@#$%^&*()"},
    {"data": "' OR 1=1 --"},
    {"id": "string_instead_of_int"},
    {"data": None},
    {"data": ""},
    {"data": "   "},
    {"data": "こんにちは"},
    {"data": "🚀🔥💻"},
    {"nested": {"level1": {"level2": "deep"}}},
    {"data": 999999999999999999999},
    {"data": "<script>alert('XSS')</script>"},
    {"data": "../../etc/passwd"},
    {"amount": -99999},
    {"date": "2026-99-99"},
    {"customer_id": "abc123"}
]

# ✅ Path setup (auto creates logs folder)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOGS_DIR, "fuzz_results.txt")
GRAPH_FILE = os.path.join(LOGS_DIR, "fuzz_results.png")


def fuzz_api():
    summary = {"success": 0, "client_error": 0, "server_error": 0, "other": 0}

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("=== Fuzz Test Results ===\n\n")

    for i, payload in enumerate(payloads, start=1):
        try:
            start = datetime.datetime.now()
            response = requests.post(API_URL, json=payload, timeout=5)
            end = datetime.datetime.now()

            response_time = (end - start).total_seconds()
            status = response.status_code

            if 200 <= status < 300:
                summary["success"] += 1
            elif 400 <= status < 500:
                summary["client_error"] += 1
            elif 500 <= status < 600:
                summary["server_error"] += 1
            else:
                summary["other"] += 1

            log = (
                f"Test {i} ({datetime.datetime.now()}):\n"
                f"Payload: {payload}\n"
                f"Status: {status}\n"
                f"Response Time: {response_time:.3f}s\n"
                f"Response: {response.text[:200]}\n"
                + "-"*50 + "\n"
            )

            print(log)

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log)

        except Exception as e:
            summary["other"] += 1
            error = f"Test {i} Error: {e}\n"
            print(error)

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(error)

    # Summary
    summary_text = (
        "\n=== Summary ===\n"
        f"Success: {summary['success']}\n"
        f"Client Errors: {summary['client_error']}\n"
        f"Server Errors: {summary['server_error']}\n"
        f"Other: {summary['other']}\n"
    )

    print(summary_text)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(summary_text)

    visualize(summary)


def visualize(summary):
    categories = ["Success", "Client Errors", "Server Errors", "Other"]
    values = [
        summary["success"],
        summary["client_error"],
        summary["server_error"],
        summary["other"]
    ]

    plt.figure(figsize=(8, 6))
    bars = plt.bar(categories, values)

    for bar, val in zip(bars, values):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                 str(val), ha='center', va='bottom')

    plt.title("Fuzz Test Results")
    plt.xlabel("Categories")
    plt.ylabel("Count")
    plt.tight_layout()

    plt.savefig(GRAPH_FILE)
    plt.show()


if __name__ == "__main__":
    fuzz_api()