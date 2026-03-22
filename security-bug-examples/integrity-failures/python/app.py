import pickle
import base64
import yaml
import time
import hashlib
import json
import importlib
import urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)

SESSIONS = {}
USERS = {}
PLUGINS = {}
WORKFLOWS = {}
CACHE = {}

user_counter = 4
workflow_counter = 0


def init_data():
    global USERS
    USERS = {
        1: {"id": 1, "username": "admin", "email": "admin@pipeline.io",
            "password": hashlib.sha256("admin2024!".encode()).hexdigest(),
            "role": "admin", "active": True},
        2: {"id": 2, "username": "jthompson", "email": "jthompson@pipeline.io",
            "password": hashlib.sha256("jenny_t99".encode()).hexdigest(),
            "role": "engineer", "active": True},
        3: {"id": 3, "username": "mgarcia", "email": "mgarcia@pipeline.io",
            "password": hashlib.sha256("marco_g!".encode()).hexdigest(),
            "role": "analyst", "active": True},
        4: {"id": 4, "username": "alee", "email": "alee@pipeline.io",
            "password": hashlib.sha256("amy_lee22".encode()).hexdigest(),
            "role": "viewer", "active": False},
    }


init_data()


def generate_token(user_id):
    raw = f"{user_id}-{time.time()}-pipeline"
    token = hashlib.sha256(raw.encode()).hexdigest()[:48]
    SESSIONS[token] = {"user_id": user_id, "created": time.time()}
    return token


def get_session():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        return SESSIONS.get(token)
    return None


def require_role(*roles):
    session = get_session()
    if not session:
        return None, (jsonify({"error": "Authentication required"}), 401)
    user = USERS.get(session["user_id"])
    if not user:
        return None, (jsonify({"error": "User not found"}), 404)
    if user["role"] not in roles:
        return None, (jsonify({"error": "Insufficient permissions"}), 403)
    return user, None


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "")
    password = data.get("password", "")
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    for uid, user in USERS.items():
        if user["username"] == username and user["password"] == password_hash:
            if not user["active"]:
                return jsonify({"error": "Account disabled"}), 403
            token = generate_token(uid)
            return jsonify({"token": token, "user_id": uid, "role": user["role"]})

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/workflows", methods=["POST"])
def create_workflow():
    session = get_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"error": "Workflow name required"}), 400

    global workflow_counter
    workflow_counter += 1

    steps = data.get("steps", [])
    workflow = {
        "id": workflow_counter,
        "name": data["name"],
        "steps": steps,
        "owner_id": session["user_id"],
        "created": time.time(),
        "status": "draft",
    }
    WORKFLOWS[workflow_counter] = workflow

    return jsonify({"id": workflow_counter, "name": data["name"],
                     "message": "Workflow created"})


@app.route("/api/workflows/<int:wf_id>", methods=["GET"])
def get_workflow(wf_id):
    session = get_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    workflow = WORKFLOWS.get(wf_id)
    if not workflow:
        return jsonify({"error": "Workflow not found"}), 404

    return jsonify(workflow)


@app.route("/api/workflows/import", methods=["POST"])
def import_workflow():
    session = get_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or "payload" not in data:
        return jsonify({"error": "Payload required"}), 400

    fmt = data.get("format", "json")

    try:
        raw_bytes = base64.b64decode(data["payload"])

        if fmt == "pickle":
            workflow_data = pickle.loads(raw_bytes)
        elif fmt == "yaml":
            workflow_data = yaml.load(raw_bytes.decode("utf-8"), Loader=yaml.Loader)
        else:
            workflow_data = json.loads(raw_bytes.decode("utf-8"))

        global workflow_counter
        workflow_counter += 1

        workflow = {
            "id": workflow_counter,
            "name": workflow_data.get("name", "Imported Workflow"),
            "steps": workflow_data.get("steps", []),
            "owner_id": session["user_id"],
            "created": time.time(),
            "status": "imported",
        }
        WORKFLOWS[workflow_counter] = workflow

        return jsonify({"id": workflow_counter, "name": workflow["name"],
                         "message": "Workflow imported"})
    except Exception as e:
        return jsonify({"error": f"Import failed: {str(e)}"}), 400


@app.route("/api/workflows/export", methods=["POST"])
def export_workflow():
    session = get_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or "workflow_id" not in data:
        return jsonify({"error": "Workflow ID required"}), 400

    workflow = WORKFLOWS.get(data["workflow_id"])
    if not workflow:
        return jsonify({"error": "Workflow not found"}), 404

    fmt = data.get("format", "json")
    export_data = {"name": workflow["name"], "steps": workflow["steps"]}

    if fmt == "pickle":
        raw = pickle.dumps(export_data)
    elif fmt == "yaml":
        raw = yaml.dump(export_data).encode("utf-8")
    else:
        raw = json.dumps(export_data).encode("utf-8")

    encoded = base64.b64encode(raw).decode("utf-8")
    return jsonify({"payload": encoded, "format": fmt})


@app.route("/api/plugins/install", methods=["POST"])
def install_plugin():
    user, err = require_role("admin", "engineer")
    if err:
        return err

    data = request.get_json()
    if not data or "module_name" not in data:
        return jsonify({"error": "Module name required"}), 400

    module_name = data["module_name"]
    source_url = data.get("source_url")

    try:
        if source_url:
            urllib.request.urlretrieve(source_url,
                                       f"/tmp/plugins/{module_name}.py")

        mod = importlib.import_module(module_name)

        plugin_info = {
            "name": module_name,
            "version": getattr(mod, "__version__", "0.0.1"),
            "description": getattr(mod, "__description__", ""),
            "installed_by": user["id"],
            "installed_at": time.time(),
        }
        PLUGINS[module_name] = plugin_info

        if hasattr(mod, "on_install"):
            mod.on_install()

        return jsonify({"message": f"Plugin '{module_name}' installed",
                         "plugin": plugin_info})
    except Exception as e:
        return jsonify({"error": f"Installation failed: {str(e)}"}), 400


@app.route("/api/plugins", methods=["GET"])
def list_plugins():
    session = get_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    return jsonify({"plugins": list(PLUGINS.values())})


@app.route("/api/plugins/<name>/execute", methods=["POST"])
def execute_plugin(name):
    session = get_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    plugin = PLUGINS.get(name)
    if not plugin:
        return jsonify({"error": "Plugin not found"}), 404

    data = request.get_json() or {}

    try:
        mod = importlib.import_module(name)
        if hasattr(mod, "execute"):
            result = mod.execute(data)
            return jsonify({"result": result})
        return jsonify({"error": "Plugin has no execute function"}), 400
    except Exception as e:
        return jsonify({"error": f"Execution failed: {str(e)}"}), 500


@app.route("/api/cache/store", methods=["POST"])
def store_cache():
    session = get_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()
    if not data or "key" not in data or "value" not in data:
        return jsonify({"error": "Key and value required"}), 400

    serialized = base64.b64encode(
        pickle.dumps(data["value"])
    ).decode("utf-8")

    CACHE[data["key"]] = {
        "data": serialized,
        "owner_id": session["user_id"],
        "stored_at": time.time(),
    }

    return jsonify({"key": data["key"], "message": "Cached"})


@app.route("/api/cache/<key>", methods=["GET"])
def get_cache(key):
    session = get_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401

    entry = CACHE.get(key)
    if not entry:
        return jsonify({"error": "Cache miss"}), 404

    value = pickle.loads(base64.b64decode(entry["data"]))

    return jsonify({"key": key, "value": value})


@app.route("/api/config/load", methods=["POST"])
def load_config():
    user, err = require_role("admin")
    if err:
        return err

    data = request.get_json()
    if not data or "config_data" not in data:
        return jsonify({"error": "Config data required"}), 400

    try:
        config = yaml.load(data["config_data"], Loader=yaml.Loader)

        app_settings = config.get("settings", {})
        pipeline_defaults = config.get("pipeline_defaults", {})

        return jsonify({
            "message": "Configuration loaded",
            "settings_count": len(app_settings),
            "pipeline_defaults": pipeline_defaults,
        })
    except Exception as e:
        return jsonify({"error": f"Config parse failed: {str(e)}"}), 400


@app.route("/api/extensions/load", methods=["POST"])
def load_extension():
    user, err = require_role("admin", "engineer")
    if err:
        return err

    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Extension URL required"}), 400

    ext_url = data["url"]
    ext_name = data.get("name", "custom_extension")

    try:
        response = urllib.request.urlopen(ext_url)
        code = response.read().decode("utf-8")

        exec(compile(code, f"<extension:{ext_name}>", "exec"))

        return jsonify({"message": f"Extension '{ext_name}' loaded",
                         "source": ext_url})
    except Exception as e:
        return jsonify({"error": f"Extension load failed: {str(e)}"}), 400


@app.route("/api/users", methods=["GET"])
def list_users():
    session = get_session()
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


@app.route("/api/users", methods=["POST"])
def create_user():
    user, err = require_role("admin")
    if err:
        return err

    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Username and password required"}), 400

    global user_counter
    user_counter += 1

    new_user = {
        "id": user_counter,
        "username": data["username"],
        "email": data.get("email", ""),
        "password": hashlib.sha256(data["password"].encode()).hexdigest(),
        "role": data.get("role", "viewer"),
        "active": True,
    }
    USERS[user_counter] = new_user

    return jsonify({"id": user_counter, "username": data["username"],
                     "message": "User created"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5008, debug=False)
