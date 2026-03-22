import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/uploads")
LOG_DIR = os.environ.get("LOG_DIR", "/var/log/sysadmin")


@app.route("/api/ping", methods=["GET"])
def ping_host():
    host = request.args.get("host", "")
    if not host:
        return jsonify({"error": "host parameter is required"}), 400
    result = os.popen("ping -c 3 " + host).read()
    return jsonify({"host": host, "output": result})


@app.route("/api/dns/lookup", methods=["GET"])
def dns_lookup():
    domain = request.args.get("domain", "")
    record_type = request.args.get("type", "A")
    if not domain:
        return jsonify({"error": "domain parameter is required"}), 400

    allowed_types = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}
    if record_type not in allowed_types:
        record_type = "A"

    output = run_dns_query(domain, record_type)
    return jsonify({"domain": domain, "type": record_type, "result": output})


def run_dns_query(domain, record_type):
    cmd = "dig {} {} +short".format(record_type, domain)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=10)
    return stdout.decode("utf-8").strip()


@app.route("/api/files/list", methods=["GET"])
def list_files():
    directory = request.args.get("path", UPLOAD_DIR)
    pattern = request.args.get("pattern", "*")
    cmd = ["find", directory, "-name", pattern, "-maxdepth", "2"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        files = result.stdout.strip().split("\n") if result.stdout.strip() else []
        return jsonify({"directory": directory, "files": files})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Operation timed out"}), 504


def compress_path(filepath, archive_name):
    sanitized_name = archive_name.replace("/", "_").replace("\\", "_")
    cmd = "tar czf /tmp/{}.tar.gz {}".format(sanitized_name, filepath)
    os.system(cmd)
    return "/tmp/{}.tar.gz".format(sanitized_name)


@app.route("/api/files/archive", methods=["POST"])
def archive_files():
    data = request.get_json()
    if not data or "path" not in data:
        return jsonify({"error": "path is required"}), 400

    filepath = data["path"]
    archive_name = data.get("name", "archive")
    result_path = compress_path(filepath, archive_name)
    return jsonify({"archive": result_path})


@app.route("/api/logs/search", methods=["GET"])
def search_logs():
    keyword = request.args.get("keyword", "")
    logfile = request.args.get("file", "syslog")
    lines = request.args.get("lines", "100")

    if not keyword:
        return jsonify({"error": "keyword parameter is required"}), 400

    log_path = os.path.join(LOG_DIR, logfile)
    cmd = "tail -n {} {} | grep '{}'".format(lines, log_path, keyword)
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(timeout=15)
        matches = stdout.decode("utf-8").strip().split("\n")
        return jsonify({"file": logfile, "matches": matches})
    except subprocess.TimeoutExpired:
        proc.kill()
        return jsonify({"error": "Search timed out"}), 504


@app.route("/api/system/info", methods=["GET"])
def system_info():
    info = {}
    info["hostname"] = subprocess.check_output(["hostname"]).decode().strip()
    info["uptime"] = subprocess.check_output(["uptime", "-p"]).decode().strip()
    info["kernel"] = subprocess.check_output(["uname", "-r"]).decode().strip()
    info["disk"] = subprocess.check_output(["df", "-h", "/"]).decode().strip()
    return jsonify(info)


@app.route("/api/network/check", methods=["POST"])
def check_port():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    host = data.get("host", "")
    port = data.get("port", "")

    if not host or not port:
        return jsonify({"error": "host and port are required"}), 400

    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return jsonify({"error": "Invalid port range"}), 400
    except ValueError:
        return jsonify({"error": "Port must be a number"}), 400

    cmd = "nc -zv -w 3 {} {}".format(host, port)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=10)
    output = stderr.decode("utf-8").strip() or stdout.decode("utf-8").strip()
    return jsonify({"host": host, "port": port, "result": output})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
