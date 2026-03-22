import os
import json
import yaml
import requests
from flask import Flask, request, jsonify
from jinja2 import Template
from lxml import etree
from cryptography.fernet import Fernet

app = Flask(__name__)

ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

PRODUCTS = {
    1: {"id": 1, "name": "Widget Pro", "price": 29.99, "stock": 150, "category": "hardware"},
    2: {"id": 2, "name": "Gadget Plus", "price": 49.99, "stock": 75, "category": "electronics"},
    3: {"id": 3, "name": "Tool Kit Standard", "price": 19.99, "stock": 200, "category": "tools"},
    4: {"id": 4, "name": "Sensor Array", "price": 89.99, "stock": 30, "category": "electronics"},
    5: {"id": 5, "name": "Cable Bundle", "price": 9.99, "stock": 500, "category": "accessories"},
}

ORDERS = {}
ORDER_COUNTER = 1000

WAREHOUSE_CONFIG = {
    "location": "us-east-1",
    "api_endpoint": "https://warehouse.internal.acmecorp.io/api/v2",
    "max_batch_size": 50,
    "retry_attempts": 3,
}


@app.route("/api/products", methods=["GET"])
def list_products():
    category = request.args.get("category")
    products = list(PRODUCTS.values())
    if category:
        products = [p for p in products if p["category"] == category]
    return jsonify({"products": products, "total": len(products)})


@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    product = PRODUCTS.get(product_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    return jsonify(product)


@app.route("/api/orders", methods=["POST"])
def create_order():
    global ORDER_COUNTER
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    items = data.get("items", [])
    if not items:
        return jsonify({"error": "At least one item required"}), 400

    order_items = []
    total = 0.0
    for item in items:
        pid = item.get("product_id")
        qty = item.get("quantity", 1)
        product = PRODUCTS.get(pid)
        if not product:
            return jsonify({"error": f"Product {pid} not found"}), 404
        if product["stock"] < qty:
            return jsonify({"error": f"Insufficient stock for {product['name']}"}), 400
        product["stock"] -= qty
        subtotal = product["price"] * qty
        total += subtotal
        order_items.append({
            "product_id": pid,
            "name": product["name"],
            "quantity": qty,
            "subtotal": round(subtotal, 2),
        })

    ORDER_COUNTER += 1
    order_id = ORDER_COUNTER
    ORDERS[order_id] = {
        "id": order_id,
        "items": order_items,
        "total": round(total, 2),
        "status": "confirmed",
        "customer_email": data.get("email", ""),
    }

    return jsonify({"order_id": order_id, "total": round(total, 2), "status": "confirmed"}), 201


@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404
    return jsonify(order)


@app.route("/api/inventory/import", methods=["POST"])
def import_inventory():
    data = request.get_json()
    if not data or "payload" not in data:
        return jsonify({"error": "Payload required"}), 400

    fmt = data.get("format", "json")
    payload = data["payload"]

    if fmt == "yaml":
        parsed = yaml.load(payload, Loader=yaml.FullLoader)
    elif fmt == "xml":
        root = etree.fromstring(payload.encode())
        parsed = {child.tag: child.text for child in root}
    else:
        parsed = json.loads(payload) if isinstance(payload, str) else payload

    updated = 0
    if isinstance(parsed, dict) and "products" in parsed:
        for entry in parsed["products"]:
            pid = entry.get("id")
            if pid and pid in PRODUCTS:
                PRODUCTS[pid]["stock"] = entry.get("stock", PRODUCTS[pid]["stock"])
                PRODUCTS[pid]["price"] = entry.get("price", PRODUCTS[pid]["price"])
                updated += 1

    return jsonify({"message": "Inventory updated", "updated_count": updated})


@app.route("/api/products/<int:product_id>/label", methods=["GET"])
def generate_label(product_id):
    product = PRODUCTS.get(product_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    template_str = request.args.get("template", "{{ name }} - ${{ price }}")
    tmpl = Template(template_str)
    label = tmpl.render(name=product["name"], price=product["price"],
                        category=product["category"], stock=product["stock"])

    return jsonify({"label": label, "product_id": product_id})


@app.route("/api/warehouse/sync", methods=["POST"])
def sync_warehouse():
    data = request.get_json()
    target_url = data.get("endpoint", WAREHOUSE_CONFIG["api_endpoint"]) if data else WAREHOUSE_CONFIG["api_endpoint"]

    inventory = [{"id": p["id"], "name": p["name"], "stock": p["stock"]} for p in PRODUCTS.values()]

    try:
        resp = requests.post(target_url, json={"inventory": inventory}, timeout=10)
        return jsonify({"status": "synced", "remote_status": resp.status_code})
    except requests.RequestException as e:
        return jsonify({"error": "Sync failed", "details": str(e)}), 502


@app.route("/api/orders/<int:order_id>/encrypt", methods=["POST"])
def encrypt_order(order_id):
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    order_json = json.dumps(order)
    encrypted = cipher.encrypt(order_json.encode()).decode()
    return jsonify({"order_id": order_id, "encrypted_data": encrypted})


@app.route("/api/config/warehouse", methods=["GET"])
def get_warehouse_config():
    return jsonify(WAREHOUSE_CONFIG)


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "inventory-api"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010, debug=False)
