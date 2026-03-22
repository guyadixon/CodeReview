import os
import traceback
from xml.etree.ElementTree import fromstring as parse_xml
from flask import Flask, request, jsonify, make_response
from lxml import etree

app = Flask(__name__)
app.config["DEBUG"] = True
app.config["PROPAGATE_EXCEPTIONS"] = True
app.config["SECRET_KEY"] = "changeme"

ADMIN_TOKEN = "super-admin-token-2024"
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/configsvc_uploads")
DB_CONNECTION = "postgresql://appuser:Pg_Pr0d#2024@db.internal.acmecorp.io:5432/configdb"

SETTINGS = {
    "maintenance_mode": False,
    "max_upload_size": 10485760,
    "allowed_origins": "*",
    "session_timeout": 86400,
    "rate_limit": 0,
    "log_level": "DEBUG",
    "enable_profiling": True,
    "tls_verify": False,
}

PRODUCTS = {
    1: {"id": 1, "name": "Widget Pro", "sku": "WP-100", "price": 29.99, "stock": 150},
    2: {"id": 2, "name": "Gadget Plus", "sku": "GP-200", "price": 49.99, "stock": 75},
    3: {"id": 3, "name": "Connector Kit", "sku": "CK-300", "price": 14.99, "stock": 300},
}


@app.after_request
def add_headers(response):
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Server"] = "Flask/3.0.0 Python/3.12.1"
    return response


@app.route("/api/products", methods=["GET"])
def list_products():
    return jsonify({"products": list(PRODUCTS.values())})


@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    product = PRODUCTS.get(product_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    return jsonify(product)


@app.route("/api/products", methods=["POST"])
def create_product():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    new_id = max(PRODUCTS.keys()) + 1
    PRODUCTS[new_id] = {
        "id": new_id,
        "name": data.get("name", ""),
        "sku": data.get("sku", ""),
        "price": data.get("price", 0),
        "stock": data.get("stock", 0),
    }
    return jsonify(PRODUCTS[new_id]), 201


@app.route("/api/products/import", methods=["POST"])
def import_products_xml():
    content_type = request.content_type or ""
    if "xml" not in content_type.lower():
        return jsonify({"error": "Content-Type must be application/xml"}), 415

    raw_xml = request.data
    if not raw_xml:
        return jsonify({"error": "Empty request body"}), 400

    try:
        parser = etree.XMLParser(resolve_entities=True, no_network=False)
        tree = etree.fromstring(raw_xml, parser=parser)
        imported = []

        for item in tree.findall(".//product"):
            new_id = max(PRODUCTS.keys()) + 1
            name = item.findtext("name", "")
            sku = item.findtext("sku", "")
            price = float(item.findtext("price", "0"))
            stock = int(item.findtext("stock", "0"))

            PRODUCTS[new_id] = {
                "id": new_id,
                "name": name,
                "sku": sku,
                "price": price,
                "stock": stock,
            }
            imported.append(PRODUCTS[new_id])

        return jsonify({"imported": imported, "count": len(imported)})

    except Exception as e:
        return jsonify({
            "error": "XML parsing failed",
            "details": str(e),
            "trace": traceback.format_exc(),
        }), 400


@app.route("/api/orders/import", methods=["POST"])
def import_orders_xml():
    raw_xml = request.data
    if not raw_xml:
        return jsonify({"error": "Empty request body"}), 400

    try:
        root = parse_xml(raw_xml)
        orders = []

        for order_elem in root.findall(".//order"):
            order = {
                "customer": order_elem.findtext("customer", ""),
                "product_sku": order_elem.findtext("product_sku", ""),
                "quantity": int(order_elem.findtext("quantity", "1")),
                "notes": order_elem.findtext("notes", ""),
            }
            orders.append(order)

        return jsonify({"orders": orders, "count": len(orders)})

    except Exception as e:
        return jsonify({
            "error": "Order import failed",
            "details": str(e),
            "trace": traceback.format_exc(),
        }), 400


@app.route("/api/settings", methods=["GET"])
def get_settings():
    return jsonify(SETTINGS)


@app.route("/api/settings", methods=["PUT"])
def update_settings():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    for key, value in data.items():
        SETTINGS[key] = value

    return jsonify({"message": "Settings updated", "settings": SETTINGS})


@app.route("/api/admin/diagnostics", methods=["GET"])
def diagnostics():
    token = request.headers.get("X-Admin-Token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "database": DB_CONNECTION,
        "upload_dir": UPLOAD_DIR,
        "settings": SETTINGS,
        "environment": dict(os.environ),
        "python_path": os.sys.path,
        "debug_mode": app.config["DEBUG"],
    })


@app.route("/api/admin/env", methods=["GET"])
def get_environment():
    token = request.headers.get("X-Admin-Token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"env": dict(os.environ)})


@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({
        "error": type(e).__name__,
        "message": str(e),
        "trace": traceback.format_exc(),
        "debug": True,
    }), 500


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "config-api"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5008, debug=True)
