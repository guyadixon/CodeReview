const express = require("express");
const crypto = require("crypto");
const http = require("http");
const https = require("https");
const { URL } = require("url");
const app = express();
app.use(express.json());

const users = {};
const sessions = {};
const webhooks = {};

function initData() {
  users[1] = {
    id: 1, username: "admin", email: "admin@acmecorp.io",
    password: "Adm1n_Pr0d!", role: "admin", active: true,
    apiKey: "ak-admin-x7k9m2",
  };
  users[2] = {
    id: 2, username: "jdoe", email: "jdoe@acmecorp.io",
    password: "JohnD_2024", role: "manager", active: true,
    apiKey: "ak-jdoe-p3q8r1",
  };
  users[3] = {
    id: 3, username: "asmith", email: "asmith@acmecorp.io",
    password: "alice_pass", role: "developer", active: true,
    apiKey: "ak-asmith-w5t6y4",
  };
}

initData();

function generateToken(userId) {
  const raw = `${userId}-${Date.now()}`;
  return crypto.createHash("sha256").update(raw).digest("hex").substring(0, 32);
}

function getSession(req) {
  const auth = (req.headers.authorization || "").replace("Bearer ", "");
  return sessions[auth] || null;
}

function fetchUrl(targetUrl) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === "https:" ? https : http;
    const req = client.get(targetUrl, { timeout: 10000 }, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out")); });
  });
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const user = Object.values(users).find((u) => u.username === username);
  if (!user || !user.active) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (user.password === password) {
    const token = generateToken(user.id);
    sessions[token] = { userId: user.id, created: Date.now() };
    return res.json({ token, userId: user.id, role: user.role });
  }

  return res.status(401).json({ error: "Invalid credentials" });
});

app.post("/api/fetch-url", async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Authentication required" });

  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: "URL parameter required" });

  try {
    const result = await fetchUrl(url);
    return res.json({
      status: result.status,
      contentLength: result.body.length,
      body: result.body.substring(0, 5000),
    });
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }
});

app.get("/api/preview", async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Authentication required" });

  const target = req.query.target || "";
  if (!target) return res.status(400).json({ error: "target parameter required" });

  try {
    const parsed = new URL(target);
    const blockedHosts = ["localhost", "127.0.0.1"];
    if (blockedHosts.includes(parsed.hostname)) {
      return res.status(403).json({ error: "Blocked host" });
    }

    const result = await fetchUrl(target);
    return res.json({
      url: target,
      contentType: result.headers["content-type"] || "",
      preview: result.body.substring(0, 2000),
    });
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }
});

app.post("/api/webhooks", (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Authentication required" });

  const { callbackUrl, eventType } = req.body || {};
  if (!callbackUrl) return res.status(400).json({ error: "callbackUrl required" });

  try {
    const parsed = new URL(callbackUrl);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ error: "Only HTTP(S) callbacks supported" });
    }
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  const webhookId = crypto.createHash("md5")
    .update(`${callbackUrl}${Date.now()}`)
    .digest("hex")
    .substring(0, 12);

  webhooks[webhookId] = {
    id: webhookId,
    callbackUrl,
    eventType: eventType || "default",
    userId: session.userId,
    created: Date.now(),
  };

  return res.status(201).json({ message: "Webhook registered", webhookId });
});

app.post("/api/webhooks/:id/test", async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Authentication required" });

  const webhook = webhooks[req.params.id];
  if (!webhook) return res.status(404).json({ error: "Webhook not found" });

  const payload = JSON.stringify({ event: "test", timestamp: Date.now() });

  try {
    const parsed = new URL(webhook.callbackUrl);
    const client = parsed.protocol === "https:" ? https : http;
    const options = {
      method: "POST",
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
      timeout: 10000,
    };

    const result = await new Promise((resolve, reject) => {
      const r = client.request(options, (response) => {
        let body = "";
        response.on("data", (chunk) => { body += chunk; });
        response.on("end", () => resolve({ status: response.statusCode }));
      });
      r.on("error", reject);
      r.write(payload);
      r.end();
    });

    return res.json({ message: "Webhook delivered", status: result.status });
  } catch (err) {
    return res.status(502).json({ error: `Delivery failed: ${err.message}` });
  }
});

app.post("/api/integrations/import", async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Authentication required" });

  const { configUrl } = req.body || {};
  if (!configUrl) return res.status(400).json({ error: "configUrl required" });

  try {
    const parsed = new URL(configUrl);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ error: "Only HTTP(S) URLs supported" });
    }

    if (parsed.hostname && parsed.hostname.startsWith("169.254")) {
      return res.status(403).json({ error: "Metadata endpoints not allowed" });
    }

    const result = await fetchUrl(configUrl);
    const config = JSON.parse(result.body);
    return res.json({ message: "Configuration imported", config });
  } catch (err) {
    if (err instanceof SyntaxError) {
      return res.status(400).json({ error: "Invalid JSON at URL" });
    }
    return res.status(502).json({ error: err.message });
  }
});

app.get("/api/proxy", async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Authentication required" });

  const { service, path, baseUrl } = req.query;

  const serviceMap = {
    analytics: "http://analytics-service:8081",
    billing: "http://billing-service:8082",
    notifications: "http://notifications-service:8083",
  };

  let resolvedBase = serviceMap[service] || "";
  if (!resolvedBase) {
    resolvedBase = baseUrl || "";
    if (!resolvedBase) return res.status(400).json({ error: "Unknown service" });
  }

  const fullUrl = resolvedBase + (path || "/");

  try {
    const result = await fetchUrl(fullUrl);
    return res.json({ status: result.status, body: result.body.substring(0, 5000) });
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }
});

app.get("/api/health", (req, res) => {
  return res.json({ status: "healthy", service: "gateway-api" });
});

const PORT = process.env.PORT || 3010;
app.listen(PORT, () => {
  console.log(`Gateway API running on port ${PORT}`);
});
