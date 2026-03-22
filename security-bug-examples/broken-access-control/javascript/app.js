const express = require("express");
const app = express();
app.use(express.json());

const users = {
  1: { id: 1, username: "alice", email: "alice@corp.io", role: "admin",
       ssn: "123-45-6789", salary: 150000, department: "engineering" },
  2: { id: 2, username: "bob", email: "bob@corp.io", role: "manager",
       ssn: "987-65-4321", salary: 95000, department: "engineering" },
  3: { id: 3, username: "charlie", email: "charlie@corp.io", role: "employee",
       ssn: "555-12-3456", salary: 72000, department: "sales" },
  4: { id: 4, username: "diana", email: "diana@corp.io", role: "employee",
       ssn: "444-33-2211", salary: 68000, department: "sales" },
};

const invoices = {
  1001: { id: 1001, owner_id: 1, amount: 5400.00, status: "paid",
          vendor: "CloudHost Inc", details: "Annual hosting contract" },
  1002: { id: 1002, owner_id: 2, amount: 1200.00, status: "pending",
          vendor: "Office Supplies Co", details: "Q3 office supplies" },
  1003: { id: 1003, owner_id: 3, amount: 890.50, status: "pending",
          vendor: "Travel Agency", details: "Conference travel booking" },
  1004: { id: 1004, owner_id: 1, amount: 25000.00, status: "draft",
          vendor: "Consulting Group", details: "Annual compliance engagement" },
};

const sessions = {
  "sess_alice": { userId: 1, role: "admin" },
  "sess_bob": { userId: 2, role: "manager" },
  "sess_charlie": { userId: 3, role: "employee" },
  "sess_diana": { userId: 4, role: "employee" },
};

function getSession(req) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  return sessions[token] || null;
}


app.get("/api/users/:id", (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const user = users[userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(user);
});

app.get("/api/invoices/:id", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const invoiceId = parseInt(req.params.id, 10);
  const invoice = invoices[invoiceId];
  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }

  res.json(invoice);
});

app.put("/api/invoices/:id", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const invoiceId = parseInt(req.params.id, 10);
  const invoice = invoices[invoiceId];
  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }

  const { amount, status, vendor, details } = req.body;
  if (amount !== undefined) invoice.amount = amount;
  if (status !== undefined) invoice.status = status;
  if (vendor !== undefined) invoice.vendor = vendor;
  if (details !== undefined) invoice.details = details;

  res.json({ message: "Invoice updated", invoice });
});

app.get("/api/admin/users", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const clientRole = req.headers["x-user-role"];
  if (clientRole !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }

  const userList = Object.values(users);
  res.json({ users: userList });
});

app.put("/api/users/:id/role", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const userId = parseInt(req.params.id, 10);
  const user = users[userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const { role } = req.body;
  user.role = role || "employee";

  res.json({ message: "Role updated", userId, newRole: user.role });
});

app.get("/api/debug/env", (req, res) => {
  res.json({
    nodeEnv: process.env.NODE_ENV || "development",
    dbUrl: process.env.DATABASE_URL || "mongodb://admin:password@db:27017/invoicedb",
    jwtSecret: process.env.JWT_SECRET || "jwt-secret-key-do-not-share",
    apiKeys: {
      payment: process.env.PAYMENT_KEY || "pk_live_abc123def456",
      email: process.env.EMAIL_KEY || "em_key_789xyz",
    },
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
  });
});

const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
  console.log(`Invoice Management API running on port ${PORT}`);
});
