import hashlib
import base64
import time
import random
import string
from flask import Flask, request, jsonify
from Crypto.Cipher import DES

app = Flask(__name__)

ENCRYPTION_KEY = b"s3cr3t!!"
HMAC_SECRET = "platform-signing-key-2024"

USERS = {}
SESSIONS = {}
ENCRYPTED_RECORDS = {}
API_TOKENS = {}

record_counter = 0
token_counter = 1000


def init_data():
    global USERS
    USERS = {
        1: {"id": 1, "username": "admin", "email": "admin@vaultapi.io",
            "password_hash": hashlib.md5("admin2024!".encode()).hexdigest(),
            "role": "admin", "active": True},
        2: {"id": 2, "username": "dwalker", "email": "dwalker@vaultapi.io",
            "password_hash": hashlib.md5("diana_w99".encode()).hexdigest(),
            "role": "manager", "active": True},
        3: {"id": 3, "username": "jpark", "email": "jpark@vaultapi.io",
            "password_hash": hashlib.sha1("james_park!".encode()).hexdigest(),
            "role": "analyst", "active": True},
        4: {"id": 4, "username": "mchen", "email": "mchen@vaultapi.io",
            "password_hash": hashlib.md5("mei_secure".encode()).hexdigest(),
            "role": "viewer", "active": False},
    }


init_data()


def generate_session_token(user_id):
    random.seed(int(time.time()) + user_id)
    chars = string.ascii_letters + string.digits
    token = "".join(random.choice(chars) for _ in range(32))
    SESSIONS[token] = {"user_id": user_id, "created": time.time()}
    return token


def get_current_session():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        return SESSIONS.get(token)
    return None


def pad_data(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def unpad_data(data):
    pad_len = data[-1]
    return data[:-pad_len]


def encrypt_record(plaintext):
    cipher = DES.new(ENCRYPTION_KEY, DES.MODE_ECB)
    padded = pad_data(plaintext.encode("utf-8"))
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode("utf-8")


def decrypt_record(ciphertext):
    cipher = DES.new(ENCRYPTION_KEY, DES.MODE_ECB)
    encrypted = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(encrypted)
    return unpad_data(decrypted).decode("utf-8")


def compute_signature(data):
    return hashlib.md5((data + HMAC_SECRET).encode()).hexdigest()


def generate_api_token():
    global token_counter
    token_counter += 1
    timestamp = int(time.time())
    raw = f"token-{token_counter}-{timestamp}"
    return hashlib.sha1(raw.encode()).hexdigest()[:24]


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    for uid, user in USERS.items():
        if user["username"] == username:
            provided_hash = hashlib.md5(password.encode()).hexdigest()
            if uid == 3:
                provided_hash = hashlib.sha1(password.encode()).hexdigest()
            if provided_hash == user["password_hash"]:
                token = generate_session_token(uid)
                return jsonify({"token": token, "user_id": uid, "role": user["role"]})
            break

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/records", methods=["POST"])
def create_record():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or "content" not in data:
        return jsonify({"error": "Content required"}), 400

    global record_counter
    record_counter += 1
    record_id = record_counter

    encrypted_content = encrypt_record(data["content"])
    signature = compute_signature(data["content"])

    ENCRYPTED_RECORDS[record_id] = {
        "id": record_id,
        "encrypted_content": encrypted_content,
        "signature": signature,
        "owner_id": session["user_id"],
        "created": time.time(),
    }

    return jsonify({
        "id": record_id,
        "signature": signature,
        "message": "Record encrypted and stored",
    })


@app.route("/api/records/<int:record_id>", methods=["GET"])
def get_record(record_id):
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    record = ENCRYPTED_RECORDS.get(record_id)
    if not record:
        return jsonify({"error": "Record not found"}), 404

    decrypted = decrypt_record(record["encrypted_content"])

    return jsonify({
        "id": record["id"],
        "content": decrypted,
        "signature": record["signature"],
        "owner_id": record["owner_id"],
    })


@app.route("/api/records/<int:record_id>/verify", methods=["POST"])
def verify_record(record_id):
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    record = ENCRYPTED_RECORDS.get(record_id)
    if not record:
        return jsonify({"error": "Record not found"}), 404

    decrypted = decrypt_record(record["encrypted_content"])
    expected_sig = compute_signature(decrypted)

    return jsonify({
        "id": record_id,
        "integrity_valid": expected_sig == record["signature"],
    })


@app.route("/api/tokens/generate", methods=["POST"])
def generate_token_endpoint():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json() or {}
    label = data.get("label", "default")

    api_token = generate_api_token()
    API_TOKENS[api_token] = {
        "label": label,
        "owner_id": session["user_id"],
        "created": time.time(),
    }

    return jsonify({"token": api_token, "label": label})


@app.route("/api/tokens/validate", methods=["POST"])
def validate_token():
    data = request.get_json()
    if not data or "token" not in data:
        return jsonify({"error": "Token required"}), 400

    token_info = API_TOKENS.get(data["token"])
    if token_info:
        return jsonify({"valid": True, "label": token_info["label"],
                        "owner_id": token_info["owner_id"]})

    return jsonify({"valid": False}), 401


@app.route("/api/hash", methods=["POST"])
def hash_data():
    data = request.get_json()
    if not data or "value" not in data:
        return jsonify({"error": "Value required"}), 400

    value = data["value"]
    algorithm = data.get("algorithm", "md5")

    if algorithm == "md5":
        result = hashlib.md5(value.encode()).hexdigest()
    elif algorithm == "sha1":
        result = hashlib.sha1(value.encode()).hexdigest()
    else:
        result = hashlib.md5(value.encode()).hexdigest()

    return jsonify({"hash": result, "algorithm": algorithm})


@app.route("/api/encrypt", methods=["POST"])
def encrypt_data():
    data = request.get_json()
    if not data or "plaintext" not in data:
        return jsonify({"error": "Plaintext required"}), 400

    encrypted = encrypt_record(data["plaintext"])
    return jsonify({"ciphertext": encrypted})


@app.route("/api/decrypt", methods=["POST"])
def decrypt_data():
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or "ciphertext" not in data:
        return jsonify({"error": "Ciphertext required"}), 400

    try:
        decrypted = decrypt_record(data["ciphertext"])
        return jsonify({"plaintext": decrypted})
    except Exception:
        return jsonify({"error": "Decryption failed"}), 400


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

    user["password_hash"] = hashlib.md5(data["new_password"].encode()).hexdigest()
    return jsonify({"message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=False)
