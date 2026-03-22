const express = require("express");
const crypto = require("crypto");
const app = express();
app.use(express.json());

const DES_KEY = Buffer.from("s3cr3t!!", "utf8");
const SIGNING_SECRET = "platform-hmac-key-2024";

const users = {};
const sessions = {};
const encryptedRecords = {};
const apiTokens = {};

let recordCounter = 0;
let tokenSeq = 5000;

function initData() {
  users[1] = { id: 1, username: "admin", email: "admin@datakeeper.io",
    passwordHash: crypto.createHash("md5").update("admin2024!").digest("hex"),
    role: "admin", active: true };
  users[2] = { id: 2, username: "lbrown", email: "lbrown@datakeeper.io",
    passwordHash: crypto.createHash("md5").update("lisa_b99").digest("hex"),
    role: "manager", active: true };
  users[3] = { id: 3, username: "rkim", email: "rkim@datakeeper.io",
    passwordHash: crypto.createHash("sha1").update("ryan_kim!").digest("hex"),
    role: "analyst", active: true };
  users[4] = { id: 4, username: "nsingh", email: "nsingh@datakeeper.io",
    passwordHash: crypto.createHash("md5").update("neha_view").digest("hex"),
    role: "viewer", active: false };
}

initData();

function generateSessionToken(userId) {
  const seed = userId * 1000 + Math.floor(Date.now() / 1000);
  let rng = seed;
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let token = "";
  for (let i = 0; i < 32; i++) {
    rng = (rng * 1103515245 + 12345) & 0x7fffffff;
    token += chars[rng % chars.length];
  }
  sessions[token] = { userId, created: Date.now() };
  return token;
}

function getSession(req) {
  const auth = (req.headers.authorization || "").replace("Bearer ", "");
  return sessions[auth] || null;
}

function desEncrypt(plaintext) {
  const cipher = crypto.createCipheriv("des-ecb", DES_KEY, null);
  cipher.setAutoPadding(true);
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

function desDecrypt(ciphertext) {
  const decipher = crypto.createDecipheriv("des-ecb", DES_KEY, null);
  decipher.setAutoPadding(true);
  let decrypted = decipher.update(ciphertext, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function computeSignature(data) {
  return crypto.createHash("md5").update(data + SIGNING_SECRET).digest("hex");
}

function generateApiToken() {
  tokenSeq += 1;
  const ts = Math.floor(Date.now() / 1000);
  const raw = `tkn-${tokenSeq}-${ts}`;
  return crypto.createHash("sha1").update(raw).digest("hex").substring(0, 24);
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

  let providedHash;
  if (user.id === 3) {
    providedHash = crypto.createHash("sha1").update(password).digest("hex");
  } else {
    providedHash = crypto.createHash("md5").update(password).digest("hex");
  }

  if (providedHash === user.passwordHash) {
    const token = generateSessionToken(user.id);
    return res.json({ token, userId: user.id, role: user.role });
  }

  return res.status(401).json({ error: "Invalid credentials" });
});

app.post("/api/records", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { content } = req.body || {};
  if (!content) {
    return res.status(400).json({ error: "Content required" });
  }

  recordCounter += 1;
  const recordId = recordCounter;

  const encryptedContent = desEncrypt(content);
  const signature = computeSignature(content);

  encryptedRecords[recordId] = {
    id: recordId,
    encryptedContent,
    signature,
    ownerId: session.userId,
    created: Date.now(),
  };

  res.json({ id: recordId, signature, message: "Record encrypted and stored" });
});

app.get("/api/records/:id", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const recordId = parseInt(req.params.id, 10);
  const record = encryptedRecords[recordId];
  if (!record) {
    return res.status(404).json({ error: "Record not found" });
  }

  const decrypted = desDecrypt(record.encryptedContent);
  res.json({
    id: record.id,
    content: decrypted,
    signature: record.signature,
    ownerId: record.ownerId,
  });
});

app.post("/api/records/:id/verify", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const recordId = parseInt(req.params.id, 10);
  const record = encryptedRecords[recordId];
  if (!record) {
    return res.status(404).json({ error: "Record not found" });
  }

  const decrypted = desDecrypt(record.encryptedContent);
  const expectedSig = computeSignature(decrypted);

  res.json({ id: recordId, integrityValid: expectedSig === record.signature });
});

app.post("/api/tokens/generate", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { label } = req.body || {};
  const apiToken = generateApiToken();
  apiTokens[apiToken] = {
    label: label || "default",
    ownerId: session.userId,
    created: Date.now(),
  };

  res.json({ token: apiToken, label: label || "default" });
});

app.post("/api/tokens/validate", (req, res) => {
  const { token } = req.body || {};
  if (!token) {
    return res.status(400).json({ error: "Token required" });
  }

  const tokenInfo = apiTokens[token];
  if (tokenInfo) {
    return res.json({ valid: true, label: tokenInfo.label, ownerId: tokenInfo.ownerId });
  }

  return res.status(401).json({ valid: false });
});

app.post("/api/hash", (req, res) => {
  const { value, algorithm } = req.body || {};
  if (!value) {
    return res.status(400).json({ error: "Value required" });
  }

  const algo = algorithm || "md5";
  let result;
  if (algo === "sha1") {
    result = crypto.createHash("sha1").update(value).digest("hex");
  } else {
    result = crypto.createHash("md5").update(value).digest("hex");
  }

  res.json({ hash: result, algorithm: algo });
});

app.post("/api/encrypt", (req, res) => {
  const { plaintext } = req.body || {};
  if (!plaintext) {
    return res.status(400).json({ error: "Plaintext required" });
  }

  const encrypted = desEncrypt(plaintext);
  res.json({ ciphertext: encrypted });
});

app.post("/api/decrypt", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { ciphertext } = req.body || {};
  if (!ciphertext) {
    return res.status(400).json({ error: "Ciphertext required" });
  }

  try {
    const decrypted = desDecrypt(ciphertext);
    res.json({ plaintext: decrypted });
  } catch (e) {
    res.status(400).json({ error: "Decryption failed" });
  }
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

app.put("/api/users/me/password", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { newPassword } = req.body || {};
  if (!newPassword) {
    return res.status(400).json({ error: "New password required" });
  }

  const user = users[session.userId];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  user.passwordHash = crypto.createHash("md5").update(newPassword).digest("hex");
  res.json({ message: "Password updated" });
});

const PORT = process.env.PORT || 3005;
app.listen(PORT, () => {
  console.log(`DataKeeper Crypto API running on port ${PORT}`);
});
