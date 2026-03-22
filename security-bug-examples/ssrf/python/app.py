import hashlib
import time
import urllib.request
import urllib.parse
import json as json_mod
from flask import Flask, request, jsonify

app = Flask(__name__)

SESSIONS = {}
CACHE = {}

USERS = {
    1: {"id": 1, "username": "admin", "email": "admin@acmecorp.io",
        "password": "Adm1n_Pr0d!", "role": "admin", "active": True,
        "api_key": "ak-admin-x7k9m2"},
    2: {"id": 2, "username": "jdoe", "email": "jdoe@acmecorp.io",
        "password": "JohnD_2024", "role": "manager", "active": True,
        "api_key": "ak-jdoe-p3q8r1"},
    3: {"id": 3, "username": "asmith", "email": "asmith@acmecorp.io",
        "password": "alice_pass", "role": "developer", "active": True,
        "api_key": "ak-asmith-w5t6y4"},
}

WEBHOOK_REGISTRY = {}


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
        if user["username"] == username and user["password"] == password:
            if not user["active"]:
                return jsonify({"error": "Account disabled"}), 403
            token = generate_token(uid)
            return jsonify({"token": token, "user_id": uid, "role": user["role"]})

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/fetch-url", methods=["POST"])
def fetch_url():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    url = data.get("url", "") if data else ""

    if not url:
        return jsonify({"error": "URL parameter required"}), 400

    try:
        resp = urllib.request.urlopen(url, timeout=10)
        content = resp.read().decode("utf-8", errors="replace")
        return jsonify({
            "status": resp.status,
            "content_length": len(content),
            "body": content[:5000],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/preview", methods=["GET"])
def preview_link():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    target = request.args.get("target", "")
    if not target:
        return jsonify({"error": "target parameter required"}), 400

    parsed = urllib.parse.urlparse(target)
    blocked_hosts = ["localhost", "127.0.0.1"]
    if parsed.hostname in blocked_hosts:
        return jsonify({"error": "Blocked host"}), 403

    try:
        resp = urllib.request.urlopen(target, timeout=10)
        content_type = resp.headers.get("Content-Type", "")
        body = resp.read().decode("utf-8", errors="replace")
        return jsonify({
            "url": target,
            "content_type": content_type,
            "preview": body[:2000],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/webhooks", methods=["POST"])
def register_webhook():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    callback_url = data.get("callback_url", "") if data else ""
    event_type = data.get("event_type", "default") if data else "default"

    if not callback_url:
        return jsonify({"error": "callback_url required"}), 400

    parsed = urllib.parse.urlparse(callback_url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "Only HTTP(S) callbacks supported"}), 400

    webhook_id = hashlib.md5(
        f"{callback_url}{time.time()}".encode()
    ).hexdigest()[:12]

    WEBHOOK_REGISTRY[webhook_id] = {
        "id": webhook_id,
        "callback_url": callback_url,
        "event_type": event_type,
        "user_id": session["user_id"],
        "created": time.time(),
    }

    return jsonify({"message": "Webhook registered", "webhook_id": webhook_id}), 201


@app.route("/api/webhooks/<webhook_id>/test", methods=["POST"])
def test_webhook(webhook_id):
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    webhook = WEBHOOK_REGISTRY.get(webhook_id)
    if not webhook:
        return jsonify({"error": "Webhook not found"}), 404

    payload = json_mod.dumps({"event": "test", "timestamp": time.time()}).encode()
    req = urllib.request.Request(
        webhook["callback_url"],
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return jsonify({
            "message": "Webhook delivered",
            "status": resp.status,
        })
    except Exception as e:
        return jsonify({"error": f"Delivery failed: {e}"}), 502


@app.route("/api/integrations/import", methods=["POST"])
def import_config():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    config_url = data.get("config_url", "") if data else ""

    if not config_url:
        return jsonify({"error": "config_url required"}), 400

    parsed = urllib.parse.urlparse(config_url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "Only HTTP(S) URLs supported"}), 400

    if parsed.hostname and parsed.hostname.startswith("169.254"):
        return jsonify({"error": "Metadata endpoints not allowed"}), 403

    try:
        resp = urllib.request.urlopen(config_url, timeout=10)
        raw = resp.read().decode("utf-8", errors="replace")
        config = json_mod.loads(raw)
        return jsonify({"message": "Configuration imported", "config": config})
    except json_mod.JSONDecodeError:
        return jsonify({"error": "Invalid JSON at URL"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/proxy", methods=["GET"])
def proxy_request():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    service = request.args.get("service", "")
    path = request.args.get("path", "/")

    service_map = {
        "analytics": "http://analytics-service:8081",
        "billing": "http://billing-service:8082",
        "notifications": "http://notifications-service:8083",
    }

    base_url = service_map.get(service, "")
    if not base_url:
        base_url = request.args.get("base_url", "")
        if not base_url:
            return jsonify({"error": "Unknown service"}), 400

    full_url = base_url + path

    try:
        resp = urllib.request.urlopen(full_url, timeout=10)
        body = resp.read().decode("utf-8", errors="replace")
        return jsonify({"status": resp.status, "body": body[:5000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "gateway-api"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010, debug=False)
