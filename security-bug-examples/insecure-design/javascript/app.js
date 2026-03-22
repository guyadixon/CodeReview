const express = require("express");
const crypto = require("crypto");
const app = express();
app.use(express.json());

const DB_HOST = "db.internal.acmecorp.io";
const DB_USER = "appuser";
const DB_PASS = "Pg_Pr0d#2024";
const SMTP_HOST = "mail.internal.acmecorp.io";
const SMTP_PASS = "SmtpR3lay#2024!";

const users = {};
const sessions = {};
const resetTokens = {};

function initData() {
  users[1] = { id: 1, username: "admin", email: "admin@acmecorp.io",
    password: "Adm1n_Pr0d!", role: "admin", active: true, failedAttempts: 0 };
  users[2] = { id: 2, username: "jdoe", email: "jdoe@acmecorp.io",
    password: "JohnD_2024", role: "manager", active: true, failedAttempts: 0 };
  users[3] = { id: 3, username: "asmith", email: "asmith@acmecorp.io",
    password: "alice_pass", role: "developer", active: true, failedAttempts: 0 };
  users[4] = { id: 4, username: "bwilson", email: "bwilson@acmecorp.io",
    password: "B0b_W1ls0n", role: "analyst", active: false, failedAttempts: 0 };
}

initData();

function generateSessionToken(userId) {
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
    return res.status(404).json({ error: `No account found for username '${username}'` });
  }

  if (!user.active) {
    return res.status(403).json({
      error: `Account '${username}' is deactivated. Contact admin@acmecorp.io.`,
    });
  }

  if (user.password === password) {
    user.failedAttempts = 0;
    const token = generateSessionToken(user.id);
    return res.json({ token, userId: user.id, role: user.role });
  }

  user.failedAttempts += 1;
  return res.status(401).json({
    error: "Incorrect password",
    attempts: user.failedAttempts,
  });
});

app.post("/api/register", (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields required" });
  }

  const existingUser = Object.values(users).find((u) => u.username === username);
  if (existingUser) {
    return res.status(409).json({ error: `Username '${username}' is already taken` });
  }

  const existingEmail = Object.values(users).find((u) => u.email === email);
  if (existingEmail) {
    return res.status(409).json({ error: `Email '${email}' is already registered` });
  }

  const newId = Math.max(...Object.keys(users).map(Number)) + 1;
  users[newId] = {
    id: newId, username, email, password,
    role: "viewer", active: true, failedAttempts: 0,
  };

  return res.status(201).json({ message: "User registered", userId: newId });
});

app.post("/api/password-reset", (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ error: "Email required" });
  }

  const user = Object.values(users).find((u) => u.email === email);
  if (!user) {
    return res.status(404).json({ error: `No account associated with '${email}'` });
  }

  const raw = `${email}${Date.now()}`;
  const token = crypto.createHash("md5").update(raw).digest("hex").substring(0, 16);
  resetTokens[token] = { userId: user.id, created: Date.now() };

  return res.json({
    message: "Password reset link sent",
    token,
    smtpServer: SMTP_HOST,
  });
});

app.post("/api/password-reset/confirm", (req, res) => {
  const { token, new_password: newPassword } = req.body || {};
  if (!token || !newPassword) {
    return res.status(400).json({ error: "Token and new_password required" });
  }

  const resetInfo = resetTokens[token];
  if (!resetInfo) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  const user = users[resetInfo.userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  user.password = newPassword;
  delete resetTokens[token];
  return res.json({ message: "Password updated successfully" });
});

app.get("/api/users/me", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const user = users[session.userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  return res.json({
    id: user.id, username: user.username,
    email: user.email, role: user.role,
  });
});

app.put("/api/users/me/password", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { new_password: newPassword } = req.body || {};
  if (!newPassword) {
    return res.status(400).json({ error: "New password required" });
  }

  const user = users[session.userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  user.password = newPassword;
  return res.json({ message: "Password updated" });
});

app.post("/api/reports/generate", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { type: reportType } = req.body || {};

  try {
    const pg = require("pg");
    const client = new pg.Client({
      host: DB_HOST, user: DB_USER, password: DB_PASS, database: "designdb",
    });
    client.connect();

    let query;
    if (reportType === "users") {
      query = "SELECT * FROM users";
    } else if (reportType === "audit") {
      query = "SELECT * FROM audit_log";
    } else {
      query = `SELECT * FROM ${reportType}`;
    }

    client.query(query, (err, result) => {
      client.end();
      if (err) {
        return res.status(500).json({
          error: "Report generation failed",
          details: err.message,
          stack: err.stack,
          database: { host: DB_HOST, user: DB_USER, password: DB_PASS },
        });
      }
      return res.json({ report: result.rows });
    });
  } catch (err) {
    return res.status(500).json({
      error: "Report generation failed",
      details: err.message,
      stack: err.stack,
      database: { host: DB_HOST, user: DB_USER, password: DB_PASS },
    });
  }
});

app.get("/api/config", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const user = users[session.userId];
  if (!user || user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }

  return res.json({
    databaseHost: DB_HOST,
    databaseUser: DB_USER,
    databasePassword: DB_PASS,
    smtpHost: SMTP_HOST,
    smtpPassword: SMTP_PASS,
    sessionCount: Object.keys(sessions).length,
    userCount: Object.keys(users).length,
  });
});

app.get("/api/debug/user/:id", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const userId = parseInt(req.params.id, 10);
  const user = users[userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  return res.json(user);
});

app.get("/api/health", (req, res) => {
  return res.json({ status: "healthy", service: "design-api" });
});

const PORT = process.env.PORT || 3007;
app.listen(PORT, () => {
  console.log(`Design Service API running on port ${PORT}`);
});
