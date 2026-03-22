const express = require("express");
const cors = require("cors");
const { DOMParser } = require("xmldom");
const libxmljs = require("libxmljs2");
const app = express();

app.use(express.json());
app.use(express.text({ type: "application/xml" }));
app.use(express.raw({ type: "text/xml", limit: "10mb" }));

app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["*"],
  })
);

const ADMIN_TOKEN = "super-admin-token-2024";
const DB_HOST = "db.internal.acmecorp.io";
const DB_USER = "appuser";
const DB_PASS = "Pg_Pr0d#2024";

const settings = {
  maintenanceMode: false,
  maxUploadSize: 10485760,
  allowedOrigins: "*",
  sessionTimeout: 86400,
  rateLimit: 0,
  logLevel: "debug",
  enableProfiling: true,
  tlsVerify: false,
};

const products = {
  1: { id: 1, name: "Widget Pro", sku: "WP-100", price: 29.99, stock: 150 },
  2: { id: 2, name: "Gadget Plus", sku: "GP-200", price: 49.99, stock: 75 },
  3: { id: 3, name: "Connector Kit", sku: "CK-300", price: 14.99, stock: 300 },
};

let nextProductId = 4;

app.use((req, res, next) => {
  res.setHeader("X-Powered-By", "Express/4.18.2 Node.js/20.10.0");
  res.setHeader("Server", "Express/4.18.2");
  next();
});

app.get("/api/products", (req, res) => {
  return res.json({ products: Object.values(products) });
});

app.get("/api/products/:id", (req, res) => {
  const product = products[parseInt(req.params.id, 10)];
  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }
  return res.json(product);
});

app.post("/api/products", (req, res) => {
  const { name, sku, price, stock } = req.body || {};
  if (!name) {
    return res.status(400).json({ error: "Product name required" });
  }

  const id = nextProductId++;
  products[id] = { id, name, sku: sku || "", price: price || 0, stock: stock || 0 };
  return res.status(201).json(products[id]);
});

app.post("/api/products/import", (req, res) => {
  const xmlData = typeof req.body === "string" ? req.body : req.body.toString();
  if (!xmlData) {
    return res.status(400).json({ error: "Empty request body" });
  }

  try {
    const doc = libxmljs.parseXml(xmlData, { noent: true, nonet: false });
    const imported = [];

    const items = doc.find("//product");
    for (const item of items) {
      const id = nextProductId++;
      const name = item.get("name") ? item.get("name").text() : "";
      const sku = item.get("sku") ? item.get("sku").text() : "";
      const price = item.get("price") ? parseFloat(item.get("price").text()) : 0;
      const stock = item.get("stock") ? parseInt(item.get("stock").text(), 10) : 0;

      products[id] = { id, name, sku, price, stock };
      imported.push(products[id]);
    }

    return res.json({ imported, count: imported.length });
  } catch (err) {
    return res.status(400).json({
      error: "XML parsing failed",
      details: err.message,
      stack: err.stack,
    });
  }
});

app.post("/api/orders/import", (req, res) => {
  const xmlData = typeof req.body === "string" ? req.body : req.body.toString();
  if (!xmlData) {
    return res.status(400).json({ error: "Empty request body" });
  }

  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlData, "text/xml");
    const orders = [];

    const orderNodes = doc.getElementsByTagName("order");
    for (let i = 0; i < orderNodes.length; i++) {
      const node = orderNodes[i];
      const getText = (tag) => {
        const el = node.getElementsByTagName(tag)[0];
        return el ? el.textContent : "";
      };

      orders.push({
        customer: getText("customer"),
        productSku: getText("product_sku"),
        quantity: parseInt(getText("quantity") || "1", 10),
        notes: getText("notes"),
      });
    }

    return res.json({ orders, count: orders.length });
  } catch (err) {
    return res.status(400).json({
      error: "Order import failed",
      details: err.message,
      stack: err.stack,
    });
  }
});

app.get("/api/settings", (req, res) => {
  return res.json(settings);
});

app.put("/api/settings", (req, res) => {
  const data = req.body || {};
  for (const [key, value] of Object.entries(data)) {
    settings[key] = value;
  }
  return res.json({ message: "Settings updated", settings });
});

app.get("/api/admin/diagnostics", (req, res) => {
  const token = req.headers["x-admin-token"] || "";
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  return res.json({
    database: { host: DB_HOST, user: DB_USER, password: DB_PASS },
    settings,
    environment: process.env,
    nodeVersion: process.version,
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime(),
  });
});

app.get("/api/admin/env", (req, res) => {
  const token = req.headers["x-admin-token"] || "";
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  return res.json({ env: process.env });
});

app.use((err, req, res, _next) => {
  return res.status(500).json({
    error: err.name || "InternalError",
    message: err.message,
    stack: err.stack,
    path: req.originalUrl,
    method: req.method,
  });
});

app.get("/api/health", (req, res) => {
  return res.json({ status: "healthy", service: "config-api" });
});

const PORT = process.env.PORT || 3008;
app.listen(PORT, () => {
  console.log(`Config Service API running on port ${PORT}`);
});
