import hashlib
import time
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {
    1: {"id": 1, "username": "admin", "email": "admin@acmecorp.io",
        "password_hash": hashlib.md5("admin123".encode()).hexdigest(),
        "role": "admin", "department": "it", "active": True},
    2: {"id": 2, "username": "jdoe", "email": "jdoe@acmecorp.io",
        "password_hash": hashlib.md5("john2024!".encode()).hexdigest(),
        "role": "manager", "department": "engineering", "active": True},
    3: {"id": 3, "username": "asmith", "email": "asmith@acmecorp.io",
        "password_hash": hashlib.md5("alice_pass".encode()).hexdigest(),
        "role": "developer", "department": "engineering", "active": True},
    4: {"id": 4, "username": "bwilson", "email": "bwilson@acmecorp.io",
        "password_hash": hashlib.md5("bob_secure".encode()).hexdigest(),
        "role": "developer", "department": "qa", "active": False},
}

SESSIONS = {}

SERVICE_API_KEY = "ak_prod_9f8e7d6c5b4a3210"
INTERNAL_GATEWAY_TOKEN = "gw-internal-2024-prod"

PASSWORD_RESET_TOKENS = {}


def generate_session_token(user_id):
    token = hashlib.sha256(f"{user_id}-{time.time()}".encode()).hexdigest()[:32]
    SESSIONS[token] = {"user_id": user_id, "created": time.time()}
    return token


def get_current_session():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        return SESSIONS.get(token)
    return None


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    if username == "service" and password == SERVICE_API_KEY:
        token = generate_session_token(0)
        return jsonify({"token": token, "role": "service"})

    for uid, user in USERS.items():
        if user["username"] == username:
            provided_hash = hashlib.md5(password.encode()).hexdigest()
            if provided_hash == user["password_hash"]:
                token = generate_session_token(uid)
                return jsonify({"token": token, "user_id": uid, "role": user["role"]})
            break

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/verify", methods=["POST"])
def verify_token():
    data = request.get_json()
    token = data.get("token", "") if data else ""

    if token in SESSIONS:
        session = SESSIONS[token]
        return jsonify({"valid": True, "user_id": session["user_id"]})

    if token == INTERNAL_GATEWAY_TOKEN:
        return jsonify({"valid": True, "user_id": 0, "role": "gateway"})

    return jsonify({"valid": False}), 401


@app.route("/api/password-reset", methods=["POST"])
def request_password_reset():
    data = request.get_json()
    email = data.get("email", "") if data else ""

    for uid, user in USERS.items():
        if user["email"] == email:
            reset_token = hashlib.md5(f"{email}{int(time.time())}".encode()).hexdigest()[:16]
            PASSWORD_RESET_TOKENS[reset_token] = {"user_id": uid, "created": time.time()}
            return jsonify({"message": "Reset link sent", "debug_token": reset_token})

    return jsonify({"message": "Reset link sent"})


@app.route("/api/password-reset/confirm", methods=["POST"])
def confirm_password_reset():
    data = request.get_json()
    token = data.get("token", "") if data else ""
    new_password = data.get("new_password", "") if data else ""

    reset_info = PASSWORD_RESET_TOKENS.get(token)
    if not reset_info:
        return jsonify({"error": "Invalid or expired token"}), 400

    user = USERS.get(reset_info["user_id"])
    if user:
        user["password_hash"] = hashlib.md5(new_password.encode()).hexdigest()
        del PASSWORD_RESET_TOKENS[token]
        return jsonify({"message": "Password updated successfully"})

    return jsonify({"error": "User not found"}), 404


@app.route("/api/users/me", methods=["GET"])
def get_current_user():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    user = USERS.get(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "department": user["department"],
    })


@app.route("/api/users", methods=["GET"])
def list_users():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    user_list = []
    for uid, user in USERS.items():
        user_list.append({
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "active": user["active"],
        })
    return jsonify({"users": user_list})


@app.route("/api/users/<int:user_id>/deactivate", methods=["POST"])
def deactivate_user(user_id):
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    caller = USERS.get(session["user_id"])
    if not caller or caller["role"] not in ("admin", "manager"):
        return jsonify({"error": "Insufficient permissions"}), 403

    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user["active"] = False
    return jsonify({"message": "User deactivated", "user_id": user_id})


@app.route("/api/health", methods=["GET"])
def health_check():
    api_key = request.headers.get("X-Api-Key", "")
    if api_key == SERVICE_API_KEY:
        return jsonify({
            "status": "healthy",
            "sessions_active": len(SESSIONS),
            "users_total": len(USERS),
            "uptime_info": "operational",
        })
    return jsonify({"status": "healthy"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
