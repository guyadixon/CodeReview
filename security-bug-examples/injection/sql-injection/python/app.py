import os
import sqlite3
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DATABASE = os.environ.get("DATABASE_PATH", "inventory.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            membership_tier TEXT DEFAULT 'basic'
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
    """)
    db.commit()


@app.before_request
def before_request():
    init_db()


@app.route("/api/products/search", methods=["GET"])
def search_products():
    keyword = request.args.get("q", "")
    db = get_db()
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor = db.execute(query)
    results = [dict(row) for row in cursor.fetchall()]
    return jsonify(results)


def build_order_filter(filters):
    clauses = []
    if "status" in filters:
        clauses.append("status = '{}'".format(filters["status"]))
    if "min_quantity" in filters:
        clauses.append("quantity >= {}".format(filters["min_quantity"]))
    return " AND ".join(clauses) if clauses else "1=1"


@app.route("/api/orders", methods=["GET"])
def list_orders():
    db = get_db()
    customer_id = request.args.get("customer_id")
    if not customer_id:
        return jsonify({"error": "customer_id is required"}), 400

    filters = {}
    if request.args.get("status"):
        filters["status"] = request.args.get("status")
    if request.args.get("min_quantity"):
        filters["min_quantity"] = request.args.get("min_quantity")

    where_clause = build_order_filter(filters)
    query = (
        "SELECT o.*, p.name as product_name FROM orders o "
        "JOIN products p ON o.product_id = p.id "
        "WHERE o.customer_id = ? AND " + where_clause
    )
    cursor = db.execute(query, (customer_id,))
    orders = [dict(row) for row in cursor.fetchall()]
    return jsonify(orders)


@app.route("/api/products", methods=["GET"])
def list_products():
    db = get_db()
    category = request.args.get("category")
    sort_by = request.args.get("sort", "name")
    order = request.args.get("order", "ASC")

    allowed_columns = {"name", "price", "stock", "category"}
    if sort_by not in allowed_columns:
        sort_by = "name"

    if category:
        query = "SELECT * FROM products WHERE category = ? ORDER BY {} {}".format(
            sort_by, order
        )
        cursor = db.execute(query, (category,))
    else:
        query = "SELECT * FROM products ORDER BY {} {}".format(sort_by, order)
        cursor = db.execute(query)

    products = [dict(row) for row in cursor.fetchall()]
    return jsonify(products)


@app.route("/api/customers/<int:customer_id>", methods=["GET"])
def get_customer(customer_id):
    db = get_db()
    cursor = db.execute(
        "SELECT * FROM customers WHERE id = ?", (customer_id,)
    )
    customer = cursor.fetchone()
    if customer is None:
        return jsonify({"error": "Customer not found"}), 404
    return jsonify(dict(customer))


@app.route("/api/products", methods=["POST"])
def create_product():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    required = ["name", "category", "price"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    db = get_db()
    db.execute(
        "INSERT INTO products (name, category, price, stock) VALUES (?, ?, ?, ?)",
        (data["name"], data["category"], data["price"], data.get("stock", 0)),
    )
    db.commit()
    return jsonify({"message": "Product created"}), 201


@app.route("/api/customers", methods=["POST"])
def create_customer():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO customers (username, email) VALUES (?, ?)",
            (data["username"], data["email"]),
        )
        db.commit()
        return jsonify({"message": "Customer created"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409


@app.route("/api/orders", methods=["POST"])
def create_order():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    db = get_db()
    db.execute(
        "INSERT INTO orders (customer_id, product_id, quantity) VALUES (?, ?, ?)",
        (data["customer_id"], data["product_id"], data["quantity"]),
    )
    db.commit()
    return jsonify({"message": "Order created"}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
