const express = require("express");
const sqlite3 = require("better-sqlite3");
const path = require("path");

const app = express();
app.use(express.json());

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, "inventory.db");
const db = sqlite3(dbPath);

db.exec(`
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
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

app.get("/api/products/search", (req, res) => {
  const keyword = req.query.q || "";
  const sql = `SELECT * FROM products WHERE name LIKE '%${keyword}%'`;
  try {
    const rows = db.prepare(sql).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function applyFilters(baseQuery, params, filters) {
  const clauses = [];
  const values = [...params];

  if (filters.status) {
    clauses.push(`o.status = '${filters.status}'`);
  }
  if (filters.minQuantity) {
    clauses.push(`o.quantity >= ${parseInt(filters.minQuantity, 10)}`);
  }

  let query = baseQuery;
  if (clauses.length > 0) {
    query += " AND " + clauses.join(" AND ");
  }
  return { query, values };
}

app.get("/api/orders", (req, res) => {
  const { customer_id, status, min_quantity } = req.query;
  if (!customer_id) {
    return res.status(400).json({ error: "customer_id is required" });
  }

  const baseQuery =
    "SELECT o.*, p.name as product_name FROM orders o " +
    "JOIN products p ON o.product_id = p.id " +
    "WHERE o.customer_id = ?";

  const filters = {};
  if (status) filters.status = status;
  if (min_quantity) filters.minQuantity = min_quantity;

  const { query, values } = applyFilters(baseQuery, [customer_id], filters);

  try {
    const rows = db.prepare(query).all(...values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/products", (req, res) => {
  const { category, sort = "name", order = "ASC" } = req.query;

  const allowedColumns = new Set(["name", "price", "stock", "category"]);
  const sortCol = allowedColumns.has(sort) ? sort : "name";

  let sql;
  const params = [];

  if (category) {
    sql = `SELECT * FROM products WHERE category = ? ORDER BY ${sortCol} ${order}`;
    params.push(category);
  } else {
    sql = `SELECT * FROM products ORDER BY ${sortCol} ${order}`;
  }

  try {
    const rows = db.prepare(sql).all(...params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/customers/:id", (req, res) => {
  const row = db
    .prepare("SELECT * FROM customers WHERE id = ?")
    .get(req.params.id);
  if (!row) {
    return res.status(404).json({ error: "Customer not found" });
  }
  res.json(row);
});

app.post("/api/products", (req, res) => {
  const { name, category, price, stock = 0 } = req.body;
  if (!name || !category || price === undefined) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  db.prepare(
    "INSERT INTO products (name, category, price, stock) VALUES (?, ?, ?, ?)"
  ).run(name, category, price, stock);
  res.status(201).json({ message: "Product created" });
});

app.post("/api/customers", (req, res) => {
  const { username, email } = req.body;
  try {
    db.prepare("INSERT INTO customers (username, email) VALUES (?, ?)").run(
      username,
      email
    );
    res.status(201).json({ message: "Customer created" });
  } catch (err) {
    res.status(409).json({ error: "Username already exists" });
  }
});

app.post("/api/orders", (req, res) => {
  const { customer_id, product_id, quantity } = req.body;
  db.prepare(
    "INSERT INTO orders (customer_id, product_id, quantity) VALUES (?, ?, ?)"
  ).run(customer_id, product_id, quantity);
  res.status(201).json({ message: "Order created" });
});

app.get("/api/reports/products", (req, res) => {
  const { fields = "name,price", category } = req.query;

  const columnList = fields
    .split(",")
    .map((f) => f.trim())
    .join(", ");

  let sql = `SELECT ${columnList} FROM products`;
  if (category) {
    sql += ` WHERE category = '${category}'`;
  }

  try {
    const rows = db.prepare(sql).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Inventory API running on port ${PORT}`);
});
