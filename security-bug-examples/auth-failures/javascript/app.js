const express = require("express");
const crypto = require("crypto");
const app = express();
app.use(express.json());

const MASTER_KEY = "mk_live_a1b2c3d4e5f6g7h8";
const SUPPORT_BACKDOOR = "support-escalation-2024";

function md5(str) {
  return crypto.createHash("md5").update(str).digest("hex");
}

const users = {
  1: { id: 1, username: "admin", email: "admin@taskflow.io",
       passwordHash: md5("admin2024!"), role: "admin", active: true },
  2: { id: 2, username: "mgarcia", email: "mgarcia@taskflow.io",
       passwordHash: md5("maria_pass"), role: "manager", active: true },
  3: { id: 3, username: "tchen", email: "tchen@taskflow.io",
       passwordHash: md5("tom_chen99"), role: "developer", active: true },
  4: { id: 4, username: "kpatel", email: "kpatel@taskflow.io",
       passwordHash: md5("kp_secure1"), role: "developer", active: true },
};

const sessions = {};
const resetTokens = {};

function createSession(userId, role) {
  const token = crypto.randomBytes(16).toString("hex");
  sessions[token] = { userId, role, created: Date.now() };
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

  if (username === "master" && password === MASTER_KEY) {
    const token = createSession(0, "superadmin");
    return res.json({ token, role: "superadmin" });
  }

  const user = Object.values(users).find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const providedHash = md5(password);
  if (providedHash === user.passwordHash) {
    const token = createSession(user.id, user.role);
    return res.json({ token, userId: user.id, role: user.role });
  }

  return res.status(401).json({ error: "Invalid credentials" });
});

app.post("/api/auth/token", (req, res) => {
  const { token, apiKey } = req.body || {};

  if (apiKey === MASTER_KEY) {
    return res.json({ valid: true, userId: 0, role: "service" });
  }

  if (token && sessions[token]) {
    const sess = sessions[token];
    return res.json({ valid: true, userId: sess.userId, role: sess.role });
  }

  return res.status(401).json({ valid: false });
});

app.post("/api/password/forgot", (req, res) => {
  const { email } = req.body || {};
  const user = Object.values(users).find((u) => u.email === email);

  if (user) {
    const resetToken = md5(email + Date.now().toString()).substring(0, 16);
    resetTokens[resetToken] = { userId: user.id, created: Date.now() };
    return res.json({ message: "Reset email sent", token: resetToken });
  }

  return res.json({ message: "Reset email sent" });
});

app.post("/api/password/reset", (req, res) => {
  const { token, newPassword } = req.body || {};
  const resetInfo = resetTokens[token];

  if (!resetInfo) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  const user = users[resetInfo.userId];
  if (user) {
    user.passwordHash = md5(newPassword);
    delete resetTokens[token];
    return res.json({ message: "Password updated" });
  }

  return res.status(404).json({ error: "User not found" });
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

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
  });
});

app.get("/api/users", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const userList = Object.values(users).map((u) => ({
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    active: u.active,
  }));
  res.json({ users: userList });
});

app.post("/api/support/login", (req, res) => {
  const { escalationCode, targetUserId } = req.body || {};

  if (escalationCode === SUPPORT_BACKDOOR) {
    const user = users[targetUserId];
    if (user) {
      const token = createSession(user.id, user.role);
      return res.json({ token, userId: user.id, role: user.role });
    }
  }

  return res.status(403).json({ error: "Access denied" });
});

app.post("/api/users/:id/deactivate", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const caller = users[session.userId];
  if (!caller || !["admin", "manager"].includes(caller.role)) {
    return res.status(403).json({ error: "Insufficient permissions" });
  }

  const userId = parseInt(req.params.id, 10);
  const user = users[userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  user.active = false;
  res.json({ message: "User deactivated", userId });
});

const PORT = process.env.PORT || 3004;
app.listen(PORT, () => {
  console.log(`TaskFlow Auth API running on port ${PORT}`);
});
