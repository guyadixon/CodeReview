const express = require("express");
const _ = require("lodash");
const moment = require("moment");
const ejs = require("ejs");
const marked = require("marked");
const axios = require("axios");

const app = express();
app.use(express.json());

const products = {
  1: { id: 1, name: "Widget Pro", price: 29.99, stock: 150, category: "hardware" },
  2: { id: 2, name: "Gadget Plus", price: 49.99, stock: 75, category: "electronics" },
  3: { id: 3, name: "Tool Kit Standard", price: 19.99, stock: 200, category: "tools" },
  4: { id: 4, name: "Sensor Array", price: 89.99, stock: 30, category: "electronics" },
  5: { id: 5, name: "Cable Bundle", price: 9.99, stock: 500, category: "accessories" },
};

const orders = {};
let orderCounter = 1000;

const warehouseConfig = {
  location: "us-east-1",
  apiEndpoint: "https://warehouse.internal.acmecorp.io/api/v2",
  maxBatchSize: 50,
  retryAttempts: 3,
};

app.get("/api/products", (req, res) => {
  const { category } = req.query;
  let result = Object.values(products);
  if (category) {
    result = result.filter((p) => p.category === category);
  }
  return res.json({ products: result, total: result.length });
});

app.get("/api/products/:id", (req, res) => {
  const product = products[parseInt(req.params.id, 10)];
  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }
  return res.json(product);
});

app.post("/api/orders", (req, res) => {
  const { items, email } = req.body || {};
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: "At least one item required" });
  }

  const orderItems = [];
  let total = 0;

  for (const item of items) {
    const product = products[item.product_id];
    if (!product) {
      return res.status(404).json({ error: `Product ${item.product_id} not found` });
    }
    const qty = item.quantity || 1;
    if (product.stock < qty) {
      return res.status(400).json({ error: `Insufficient stock for ${product.name}` });
    }
    product.stock -= qty;
    const subtotal = Math.round(product.price * qty * 100) / 100;
    total += subtotal;
    orderItems.push({
      product_id: product.id,
      name: product.name,
      quantity: qty,
      subtotal,
    });
  }

  orderCounter += 1;
  const orderId = orderCounter;
  orders[orderId] = {
    id: orderId,
    items: orderItems,
    total: Math.round(total * 100) / 100,
    status: "confirmed",
    customer_email: email || "",
    created_at: moment().format("YYYY-MM-DD HH:mm:ss"),
  };

  return res.status(201).json({
    order_id: orderId,
    total: Math.round(total * 100) / 100,
    status: "confirmed",
  });
});

app.get("/api/orders/:id", (req, res) => {
  const order = orders[parseInt(req.params.id, 10)];
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }
  return res.json(order);
});

app.post("/api/inventory/import", (req, res) => {
  const { payload, format } = req.body || {};
  if (!payload) {
    return res.status(400).json({ error: "Payload required" });
  }

  let data;
  try {
    data = typeof payload === "string" ? JSON.parse(payload) : payload;
  } catch (e) {
    return res.status(400).json({ error: "Invalid payload", details: e.message });
  }

  let updated = 0;
  if (data.products && Array.isArray(data.products)) {
    for (const entry of data.products) {
      const existing = products[entry.id];
      if (existing) {
        _.merge(existing, _.pick(entry, ["stock", "price"]));
        updated++;
      }
    }
  }

  return res.json({ message: "Inventory updated", updated_count: updated });
});

app.get("/api/products/:id/label", (req, res) => {
  const product = products[parseInt(req.params.id, 10)];
  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }

  const template = req.query.template || "<%= name %> - $<%= price %>";
  const label = ejs.render(template, {
    name: product.name,
    price: product.price,
    category: product.category,
    stock: product.stock,
  });

  return res.json({ label, product_id: product.id });
});

app.post("/api/warehouse/sync", async (req, res) => {
  const { endpoint } = req.body || {};
  const target = endpoint || warehouseConfig.apiEndpoint;

  const inventory = Object.values(products).map((p) => ({
    id: p.id,
    name: p.name,
    stock: p.stock,
  }));

  try {
    const resp = await axios.post(target, { inventory }, { timeout: 10000 });
    return res.json({ status: "synced", remote_status: resp.status });
  } catch (err) {
    return res.status(502).json({ error: "Sync failed", details: err.message });
  }
});

app.get("/api/products/:id/description", (req, res) => {
  const product = products[parseInt(req.params.id, 10)];
  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }

  const markdown = req.query.md || `**${product.name}** - ${product.category}`;
  const html = marked.parse(markdown);
  return res.json({ html, product_id: product.id });
});

app.get("/api/config/warehouse", (req, res) => {
  return res.json(warehouseConfig);
});

app.get("/api/health", (req, res) => {
  return res.json({ status: "healthy", service: "inventory-api" });
});

const PORT = process.env.PORT || 3010;
app.listen(PORT, () => {
  console.log(`Inventory Service API running on port ${PORT}`);
});
