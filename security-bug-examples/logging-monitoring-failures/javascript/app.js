const express = require("express");
const crypto = require("crypto");
const app = express();
app.use(express.json());

const API_SECRET = "sk-prod-logging-8a7b6c5d4e3f";

const users = {};
const sessions = {};
const transactions = [];

function initData() {
  users[1] = {
    id: 1, username: "admin", email: "admin@acmecorp.io",
    password: "Adm1n_Pr0d!", role: "admin", active: true,
    mfaEnabled: true, apiKey: "ak-admin-x7k9m2",
  };
  users[2] = {
    id: 2, username: "jdoe", email: "jdoe@acmecorp.io",
    password: "JohnD_2024", role: "manager", active: true,
    mfaEnabled: false, apiKey: "ak-jdoe-p3q8r1",
  };
  users[3] = {
    id: 3, username: "asmith", email: "asmith@acmecorp.io",
    password: "alice_pass", role: "developer", active: true,
    mfaEnabled: false, apiKey: "ak-asmith-w5t6y4",
  };
  users[4] = {
    id: 4, username: "bwilson", email: "bwilson@acmecorp.io",
    password: "B0b_W1ls0n", role: "analyst", active: false,
    mfaEnabled: false, apiKey: "ak-bwilson-z2v8n3",
  };
}

initData();

function generateToken(userId) {
  const raw = `${userId}-${Date.now()}`;
  const token = crypto.createHash("sha256").update(raw).digest("hex").substring(0, 32);
  sessions[token] = { userId, created: Date.now() };
  return token;
}

function getSession(req) {
  const auth = (req.headers.authorization || "").replace("Bearer ", "");
  return sessions[auth] || null;
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const user = Object.values(users).find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (!user.active) {
    return res.status(403).json({ error: "Account disabled" });
  }

  if (user.password === password) {
    const token = generateToken(user.id);
    return res.json({
      token,
      userId: user.id,
      role: user.role,
      password: user.password,
      apiKey: user.apiKey,
    });
  }

  return res.status(401).json({ error: "Invalid credentials" });
});

app.get("/api/admin/users", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const caller = users[session.userId];
  if (!caller) {
    return res.status(404).json({ error: "User not found" });
  }

  const result = Object.values(users).map((u) => ({
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    active: u.active,
  }));
  return res.json({ users: result });
});

app.put("/api/admin/users/:id/role", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const caller = users[session.userId];
  if (!caller) {
    return res.status(404).json({ error: "User not found" });
  }

  const targetId = parseInt(req.params.id, 10);
  const target = users[targetId];
  if (!target) {
    return res.status(404).json({ error: "Target user not found" });
  }

  const { role } = req.body || {};
  const oldRole = target.role;
  target.role = role;

  return res.json({
    message: "Role updated",
    userId: targetId,
    oldRole,
    newRole: role,
  });
});

app.post("/api/admin/users/:id/deactivate", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const caller = users[session.userId];
  if (!caller || caller.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }

  const targetId = parseInt(req.params.id, 10);
  const target = users[targetId];
  if (!target) {
    return res.status(404).json({ error: "Target user not found" });
  }

  target.active = false;
  return res.json({ message: "User deactivated", userId: targetId });
});

app.post("/api/transactions", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { amount, recipient, description } = req.body || {};
  if (!recipient) {
    return res.status(400).json({ error: "Recipient required" });
  }

  const transaction = {
    id: transactions.length + 1,
    userId: session.userId,
    amount: amount || 0,
    recipient,
    description: description || "",
    timestamp: Date.now(),
    status: "completed",
  };
  transactions.push(transaction);

  return res.status(201).json({ message: "Transaction completed", transaction });
});

app.post("/api/transactions/bulk", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { transfers } = req.body || {};
  if (!Array.isArray(transfers)) {
    return res.status(400).json({ error: "Transfers array required" });
  }

  const results = transfers.map((t) => {
    const transaction = {
      id: transactions.length + 1,
      userId: session.userId,
      amount: t.amount || 0,
      recipient: t.recipient || "",
      description: t.description || "",
      timestamp: Date.now(),
      status: "completed",
    };
    transactions.push(transaction);
    return transaction;
  });

  return res.status(201).json({
    message: `${results.length} transfers completed`,
    transactions: results,
  });
});

app.post("/api/export/data", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { type } = req.body || {};

  if (type === "users") {
    const exportData = Object.values(users).map((u) => ({
      id: u.id,
      username: u.username,
      email: u.email,
      password: u.password,
      apiKey: u.apiKey,
      role: u.role,
    }));
    return res.json({ export: exportData });
  }

  if (type === "transactions") {
    return res.json({ export: transactions });
  }

  return res.status(400).json({ error: "Unknown export type" });
});

app.post("/api/settings/api-key", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const user = users[session.userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const oldKey = user.apiKey;
  const newKey = "ak-" + crypto.createHash("md5")
    .update(`${user.username}${Date.now()}`)
    .digest("hex")
    .substring(0, 12);
  user.apiKey = newKey;

  return res.json({ message: "API key regenerated", oldKey, newKey });
});

app.put("/api/settings/mfa", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const user = users[session.userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const { enabled } = req.body || {};
  user.mfaEnabled = !!enabled;

  return res.json({ message: "MFA setting updated", mfaEnabled: user.mfaEnabled });
});

app.post("/api/validate-key", (req, res) => {
  const { api_key: apiKey } = req.body || {};

  const user = Object.values(users).find((u) => u.apiKey === apiKey);
  if (user) {
    return res.json({
      valid: true,
      userId: user.id,
      username: user.username,
      role: user.role,
    });
  }

  return res.status(401).json({ valid: false });
});

app.get("/api/health", (req, res) => {
  return res.json({ status: "healthy", service: "logging-api" });
});

const PORT = process.env.PORT || 3009;
app.listen(PORT, () => {
  console.log(`Logging Monitor API running on port ${PORT}`);
});
