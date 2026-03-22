import hashlib
import os
import sqlite3
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

DATABASE_PATH = os.environ.get("DB_PATH", "/tmp/loggingsvc.db")
API_KEY_INTERNAL = "sk-prod-9f8a7b6c5d4e3f2a1b0c"

USERS = {
    1: {"id": 1, "username": "admin", "email": "admin@acmecorp.io",
        "password": "Adm1n_Pr0d!", "role": "admin", "active": True,
        "mfa_enabled": True, "api_key": "ak-admin-x7k9m2"},
    2: {"id": 2, "username": "jdoe", "email": "jdoe@acmecorp.io",
        "password": "JohnD_2024", "role": "manager", "active": True,
        "mfa_enabled": False, "api_key": "ak-jdoe-p3q8r1"},
    3: {"id": 3, "username": "asmith", "email": "asmith@acmecorp.io",
        "password": "alice_pass", "role": "developer", "active": True,
        "mfa_enabled": False, "api_key": "ak-asmith-w5t6y4"},
    4: {"id": 4, "username": "bwilson", "email": "bwilson@acmecorp.io",
        "password": "B0b_W1ls0n", "role": "analyst", "active": False,
        "mfa_enabled": False, "api_key": "ak-bwilson-z2v8n3"},
}

SESSIONS = {}
TRANSACTIONS = []


def generate_token(user_id):
    raw = f"{user_id}-{time.time()}"
    token = hashlib.sha256(raw.encode()).hexdigest()[:32]
    SESSIONS[token] = {"user_id": user_id, "created": time.time()}
    return token


def get_current_session():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return SESSIONS.get(auth[7:])
    return None


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    for uid, user in USERS.items():
        if user["username"] == username:
            if not user["active"]:
                return jsonify({"error": "Account disabled"}), 403

            if user["password"] == password:
                token = generate_token(uid)
                return jsonify({
                    "token": token,
                    "user_id": uid,
                    "role": user["role"],
                    "password": user["password"],
                    "api_key": user["api_key"],
                })

            return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/admin/users", methods=["GET"])
def list_users():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    user = USERS.get(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    result = []
    for uid, u in USERS.items():
        result.append({
            "id": u["id"],
            "username": u["username"],
            "email": u["email"],
            "role": u["role"],
            "active": u["active"],
        })
    return jsonify({"users": result})


@app.route("/api/admin/users/<int:user_id>/role", methods=["PUT"])
def change_user_role(user_id):
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    caller = USERS.get(session["user_id"])
    if not caller:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    new_role = data.get("role", "") if data else ""

    target = USERS.get(user_id)
    if not target:
        return jsonify({"error": "Target user not found"}), 404

    old_role = target["role"]
    target["role"] = new_role
    return jsonify({
        "message": "Role updated",
        "user_id": user_id,
        "old_role": old_role,
        "new_role": new_role,
    })


@app.route("/api/admin/users/<int:user_id>/deactivate", methods=["POST"])
def deactivate_user(user_id):
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    caller = USERS.get(session["user_id"])
    if not caller or caller["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403

    target = USERS.get(user_id)
    if not target:
        return jsonify({"error": "Target user not found"}), 404

    target["active"] = False
    return jsonify({"message": "User deactivated", "user_id": user_id})


@app.route("/api/transactions", methods=["POST"])
def create_transaction():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    amount = data.get("amount", 0)
    recipient = data.get("recipient", "")
    description = data.get("description", "")

    if not recipient:
        return jsonify({"error": "Recipient required"}), 400

    transaction = {
        "id": len(TRANSACTIONS) + 1,
        "user_id": session["user_id"],
        "amount": amount,
        "recipient": recipient,
        "description": description,
        "timestamp": time.time(),
        "status": "completed",
    }
    TRANSACTIONS.append(transaction)

    return jsonify({"message": "Transaction completed", "transaction": transaction}), 201


@app.route("/api/transactions/bulk", methods=["POST"])
def bulk_transfer():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    transfers = data.get("transfers", []) if data else []

    results = []
    for t in transfers:
        transaction = {
            "id": len(TRANSACTIONS) + 1,
            "user_id": session["user_id"],
            "amount": t.get("amount", 0),
            "recipient": t.get("recipient", ""),
            "description": t.get("description", ""),
            "timestamp": time.time(),
            "status": "completed",
        }
        TRANSACTIONS.append(transaction)
        results.append(transaction)

    return jsonify({"message": f"{len(results)} transfers completed", "transactions": results}), 201


@app.route("/api/export/data", methods=["POST"])
def export_data():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    export_type = data.get("type", "") if data else ""

    if export_type == "users":
        export_records = []
        for uid, u in USERS.items():
            export_records.append({
                "id": u["id"],
                "username": u["username"],
                "email": u["email"],
                "password": u["password"],
                "api_key": u["api_key"],
                "role": u["role"],
            })
        return jsonify({"export": export_records})

    if export_type == "transactions":
        return jsonify({"export": TRANSACTIONS})

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {export_type}")
        rows = cursor.fetchall()
        conn.close()
        return jsonify({"export": [list(r) for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/settings/api-key", methods=["POST"])
def regenerate_api_key():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    user = USERS.get(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    old_key = user["api_key"]
    new_key = "ak-" + hashlib.md5(
        f"{user['username']}{time.time()}".encode()
    ).hexdigest()[:12]
    user["api_key"] = new_key

    return jsonify({
        "message": "API key regenerated",
        "old_key": old_key,
        "new_key": new_key,
    })


@app.route("/api/settings/mfa", methods=["PUT"])
def toggle_mfa():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    user = USERS.get(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    enabled = data.get("enabled", False) if data else False
    user["mfa_enabled"] = enabled

    return jsonify({"message": "MFA setting updated", "mfa_enabled": enabled})


@app.route("/api/validate-key", methods=["POST"])
def validate_api_key():
    data = request.get_json()
    key = data.get("api_key", "") if data else ""

    for uid, user in USERS.items():
        if user["api_key"] == key:
            return jsonify({
                "valid": True,
                "user_id": uid,
                "username": user["username"],
                "role": user["role"],
            })

    return jsonify({"valid": False}), 401


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "logging-api"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5009, debug=False)
