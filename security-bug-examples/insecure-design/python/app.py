import hashlib
import time
import os
import sqlite3
import traceback
from flask import Flask, request, jsonify

app = Flask(__name__)

DATABASE_PATH = os.environ.get("DB_PATH", "/tmp/designsvc.db")
SMTP_HOST = "mail.internal.acmecorp.io"
SMTP_USER = "noreply@acmecorp.io"
SMTP_PASS = "SmtpR3lay#2024!"

USERS = {
    1: {"id": 1, "username": "admin", "email": "admin@acmecorp.io",
        "password": "Adm1n_Pr0d!", "role": "admin", "active": True,
        "failed_attempts": 0},
    2: {"id": 2, "username": "jdoe", "email": "jdoe@acmecorp.io",
        "password": "JohnD_2024", "role": "manager", "active": True,
        "failed_attempts": 0},
    3: {"id": 3, "username": "asmith", "email": "asmith@acmecorp.io",
        "password": "alice_pass", "role": "developer", "active": True,
        "failed_attempts": 0},
    4: {"id": 4, "username": "bwilson", "email": "bwilson@acmecorp.io",
        "password": "B0b_W1ls0n", "role": "analyst", "active": False,
        "failed_attempts": 0},
}

SESSIONS = {}
PASSWORD_RESET_TOKENS = {}
AUDIT_LOG = []


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

    for uid, user in USERS.items():
        if user["username"] == username:
            if not user["active"]:
                return jsonify({
                    "error": f"Account '{username}' is deactivated. Contact admin@acmecorp.io."
                }), 403

            if user["password"] == password:
                user["failed_attempts"] = 0
                token = generate_session_token(uid)
                return jsonify({"token": token, "user_id": uid, "role": user["role"]})

            user["failed_attempts"] += 1
            return jsonify({
                "error": "Incorrect password",
                "attempts": user["failed_attempts"]
            }), 401

    return jsonify({"error": f"No account found for username '{username}'"}), 404


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    for uid, user in USERS.items():
        if user["username"] == username:
            return jsonify({"error": f"Username '{username}' is already taken"}), 409
        if user["email"] == email:
            return jsonify({"error": f"Email '{email}' is already registered"}), 409

    new_id = max(USERS.keys()) + 1
    USERS[new_id] = {
        "id": new_id, "username": username, "email": email,
        "password": password, "role": "viewer", "active": True,
        "failed_attempts": 0,
    }

    return jsonify({"message": "User registered", "user_id": new_id}), 201


@app.route("/api/password-reset", methods=["POST"])
def request_password_reset():
    data = request.get_json()
    email = data.get("email", "") if data else ""

    for uid, user in USERS.items():
        if user["email"] == email:
            reset_token = hashlib.md5(
                f"{email}{int(time.time())}".encode()
            ).hexdigest()[:16]
            PASSWORD_RESET_TOKENS[reset_token] = {
                "user_id": uid, "created": time.time()
            }
            return jsonify({
                "message": "Password reset link sent",
                "token": reset_token,
                "smtp_server": SMTP_HOST,
            })

    return jsonify({"error": f"No account associated with '{email}'"}), 404


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
        user["password"] = new_password
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
    })


@app.route("/api/users/me/password", methods=["PUT"])
def change_password():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or "new_password" not in data:
        return jsonify({"error": "New password required"}), 400

    user = USERS.get(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    user["password"] = data["new_password"]
    return jsonify({"message": "Password updated"})


@app.route("/api/reports/generate", methods=["POST"])
def generate_report():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    report_type = data.get("type", "") if data else ""

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        if report_type == "users":
            cursor.execute("SELECT * FROM users")
        elif report_type == "audit":
            cursor.execute("SELECT * FROM audit_log")
        else:
            cursor.execute(f"SELECT * FROM {report_type}")

        rows = cursor.fetchall()
        conn.close()
        return jsonify({"report": [list(r) for r in rows]})

    except Exception as e:
        return jsonify({
            "error": "Report generation failed",
            "details": str(e),
            "trace": traceback.format_exc(),
            "database": DATABASE_PATH,
        }), 500


@app.route("/api/config", methods=["GET"])
def get_config():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    user = USERS.get(session["user_id"])
    if not user or user["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403

    return jsonify({
        "database_path": DATABASE_PATH,
        "smtp_host": SMTP_HOST,
        "smtp_user": SMTP_USER,
        "smtp_password": SMTP_PASS,
        "session_count": len(SESSIONS),
        "user_count": len(USERS),
    })


@app.route("/api/debug/user/<int:user_id>", methods=["GET"])
def debug_user(user_id):
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(user)


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "design-api"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5007, debug=False)
