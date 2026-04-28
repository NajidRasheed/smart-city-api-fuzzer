# vulnerable_server.py
# A deliberately vulnerable local API for fuzz testing purposes (FYP demo target)

from flask import Flask, request, jsonify
import time

app = Flask(__name__)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # VULNERABILITY 1: SQL Injection simulation
    if "'" in str(username) or "OR 1=1" in str(username) or "--" in str(username):
        return jsonify({"error": "DB Error: syntax error near unexpected token", "query": f"SELECT * FROM users WHERE username='{username}'"}), 500

    # VULNERABILITY 2: Buffer overflow simulation
    if len(str(username)) > 1000 or len(str(password)) > 1000:
        return jsonify({"error": "Stack overflow: input exceeded buffer limit"}), 500

    # VULNERABILITY 3: Type confusion
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Internal TypeError: expected string"}), 500

    # VULNERABILITY 4: Null crash
    if username is None or password is None:
        return jsonify({"error": "NullPointerException: field cannot be null"}), 500

    return jsonify({"message": "Login successful", "token": "abc123"}), 200


@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '')

    # VULNERABILITY 5: XSS reflection (echoes input back unsanitised)
    if "<script>" in str(query).lower():
        return jsonify({"results": f"Search results for: {query}", "warning": "REFLECTED_XSS_DETECTED"}), 200

    # VULNERABILITY 6: Path traversal
    if "../" in str(query) or "etc/passwd" in str(query):
        return jsonify({"error": "FileNotFoundError: /etc/passwd", "path": query}), 500

    return jsonify({"results": f"Search results for: {query}"}), 200


@app.route('/api/transfer', methods=['POST'])
def transfer():
    data = request.get_json()
    amount = data.get('amount', 0)
    date = data.get('date', '')

    # VULNERABILITY 7: Negative amount (business logic flaw)
    if isinstance(amount, (int, float)) and amount < 0:
        return jsonify({"error": "Invalid transaction: negative amount accepted", "amount": amount}), 400

    # VULNERABILITY 8: Malformed date crashes parser
    if date and len(str(date)) > 0:
        parts = str(date).split('-')
        if len(parts) == 3:
            try:
                month = int(parts[1])
                day = int(parts[2])
                if month > 12 or day > 31:
                    return jsonify({"error": "DateParseException: invalid month/day value"}), 500
            except:
                return jsonify({"error": "DateParseException: could not parse date"}), 500

    return jsonify({"message": "Transfer successful"}), 200


if __name__ == '__main__':
    app.run(port=5000, debug=True)