import os
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {
    1: {"id": 1, "username": "alice", "email": "alice@company.com", "role": "admin",
        "ssn": "123-45-6789", "salary": 150000, "department": "engineering"},
    2: {"id": 2, "username": "bob", "email": "bob@company.com", "role": "manager",
        "ssn": "987-65-4321", "salary": 95000, "department": "engineering"},
    3: {"id": 3, "username": "charlie", "email": "charlie@company.com", "role": "employee",
        "ssn": "555-12-3456", "salary": 72000, "department": "marketing"},
    4: {"id": 4, "username": "diana", "email": "diana@company.com", "role": "employee",
        "ssn": "444-33-2211", "salary": 68000, "department": "marketing"},
}

DOCUMENTS = {
    101: {"id": 101, "title": "Q4 Financial Report", "owner_id": 1, "classification": "confidential",
          "content": "Revenue: $12.4M, Net Income: $3.1M, Operating Costs: $9.3M"},
    102: {"id": 102, "title": "Team Roster", "owner_id": 2, "classification": "internal",
          "content": "Engineering team: 14 members, 3 open positions"},
    103: {"id": 103, "title": "Marketing Plan", "owner_id": 3, "classification": "internal",
          "content": "Campaign budget: $500K, Target: 10K new signups"},
    104: {"id": 104, "title": "Board Meeting Notes", "owner_id": 1, "classification": "confidential",
          "content": "Acquisition target: Acme Corp, Offer: $45M"},
}

SESSIONS = {
    "token_alice": {"user_id": 1, "role": "admin"},
    "token_bob": {"user_id": 2, "role": "manager"},
    "token_charlie": {"user_id": 3, "role": "employee"},
    "token_diana": {"user_id": 4, "role": "employee"},
}

AUDIT_LOG = []


def get_current_user(req):
    token = req.headers.get("Authorization", "").replace("Bearer ", "")
    return SESSIONS.get(token)


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user_profile(user_id):
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)


@app.route("/api/users/<int:user_id>/salary", methods=["PUT"])
def update_salary(user_id):
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    if session["role"] not in ("admin", "manager"):
        return jsonify({"error": "Insufficient permissions"}), 403

    data = request.get_json()
    new_salary = data.get("salary")
    if not new_salary:
        return jsonify({"error": "salary field is required"}), 400

    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user["salary"] = new_salary
    return jsonify({"message": "Salary updated", "user_id": user_id, "new_salary": new_salary})


@app.route("/api/documents/<int:doc_id>", methods=["GET"])
def get_document(doc_id):
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404

    return jsonify(doc)



@app.route("/api/documents/<int:doc_id>", methods=["PUT"])
def update_document(doc_id):
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404

    data = request.get_json()
    if "title" in data:
        doc["title"] = data["title"]
    if "content" in data:
        doc["content"] = data["content"]
    if "classification" in data:
        doc["classification"] = data["classification"]

    return jsonify({"message": "Document updated", "document": doc})


@app.route("/api/admin/users", methods=["GET"])
def list_all_users():
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    role = request.headers.get("X-User-Role", "employee")
    if role != "admin":
        return jsonify({"error": "Admin access required"}), 403

    user_list = []
    for uid, user in USERS.items():
        user_list.append(user)
    return jsonify({"users": user_list})


@app.route("/api/users/<int:user_id>/role", methods=["PUT"])
def update_user_role(user_id):
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    new_role = data.get("role", "employee")

    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user["role"] = new_role
    if session:
        session_token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if SESSIONS.get(session_token, {}).get("user_id") == user_id:
            SESSIONS[session_token]["role"] = new_role

    return jsonify({"message": "Role updated", "user_id": user_id, "new_role": new_role})


@app.route("/api/debug/config", methods=["GET"])
def debug_config():
    config = {
        "database_url": os.environ.get("DATABASE_URL", "postgresql://admin:s3cret@db:5432/hrdb"),
        "secret_key": os.environ.get("SECRET_KEY", "super-secret-key-12345"),
        "api_keys": {
            "stripe": os.environ.get("STRIPE_KEY", "sk_live_abc123"),
            "sendgrid": os.environ.get("SENDGRID_KEY", "SG.xyz789"),
        },
        "debug_mode": True,
        "session_count": len(SESSIONS),
    }
    return jsonify(config)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=False)
