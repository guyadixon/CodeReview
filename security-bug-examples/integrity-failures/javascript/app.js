const express = require("express");
const crypto = require("crypto");
const vm = require("vm");
const https = require("https");
const http = require("http");
const { serialize, deserialize } = require("node-serialize");

const app = express();
app.use(express.json({ limit: "5mb" }));

const users = {};
const sessions = {};
const jobs = {};
const templates = {};
const dataStore = {};

let jobSeq = 0;
let templateSeq = 0;
let userSeq = 4;

function initData() {
  users[1] = { id: 1, username: "admin", email: "admin@taskrunner.io",
    passwordHash: sha256("admin2024!"), role: "admin", active: true };
  users[2] = { id: 2, username: "kpatel", email: "kpatel@taskrunner.io",
    passwordHash: sha256("kiran_p99"), role: "engineer", active: true };
  users[3] = { id: 3, username: "rjones", email: "rjones@taskrunner.io",
    passwordHash: sha256("rachel_j!"), role: "analyst", active: true };
  users[4] = { id: 4, username: "twang", email: "twang@taskrunner.io",
    passwordHash: sha256("tony_w22"), role: "viewer", active: false };
}

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

initData();

function generateToken(userId) {
  const raw = `${userId}-${Date.now()}-taskrunner`;
  const token = sha256(raw).substring(0, 48);
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

  const hash = sha256(password);
  const user = Object.values(users).find(
    (u) => u.username === username && u.passwordHash === hash
  );

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  if (!user.active) {
    return res.status(403).json({ error: "Account disabled" });
  }

  const token = generateToken(user.id);
  res.json({ token, userId: user.id, role: user.role });
});

app.post("/api/jobs", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { name, steps } = req.body || {};
  if (!name) {
    return res.status(400).json({ error: "Job name required" });
  }

  jobSeq += 1;
  jobs[jobSeq] = {
    id: jobSeq,
    name,
    steps: steps || [],
    ownerId: session.userId,
    created: Date.now(),
    status: "pending",
  };

  res.json({ id: jobSeq, name, message: "Job created" });
});

app.get("/api/jobs/:id", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const job = jobs[parseInt(req.params.id, 10)];
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }
  res.json(job);
});

app.post("/api/jobs/import", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { payload } = req.body || {};
  if (!payload) {
    return res.status(400).json({ error: "Payload required" });
  }

  try {
    const jobData = deserialize(payload);

    jobSeq += 1;
    jobs[jobSeq] = {
      id: jobSeq,
      name: jobData.name || "Imported Job",
      steps: jobData.steps || [],
      ownerId: session.userId,
      created: Date.now(),
      status: "imported",
    };

    res.json({ id: jobSeq, name: jobs[jobSeq].name, message: "Job imported" });
  } catch (e) {
    res.status(400).json({ error: "Import failed: " + e.message });
  }
});

app.post("/api/jobs/export", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { jobId } = req.body || {};
  const job = jobs[jobId];
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }

  const exportData = serialize({ name: job.name, steps: job.steps });
  res.json({ payload: exportData, format: "node-serialize" });
});

app.post("/api/templates", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { name, body: templateBody } = req.body || {};
  if (!name || !templateBody) {
    return res.status(400).json({ error: "Name and body required" });
  }

  templateSeq += 1;
  templates[templateSeq] = {
    id: templateSeq,
    name,
    body: templateBody,
    ownerId: session.userId,
    created: Date.now(),
  };

  res.json({ id: templateSeq, name, message: "Template created" });
});

app.post("/api/templates/:id/render", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const template = templates[parseInt(req.params.id, 10)];
  if (!template) {
    return res.status(404).json({ error: "Template not found" });
  }

  const variables = req.body.variables || {};

  try {
    const sandbox = { variables, output: "" };
    const script = `output = \`${template.body}\`;`;
    vm.createContext(sandbox);
    vm.runInContext(script, sandbox, { timeout: 3000 });

    res.json({ rendered: sandbox.output });
  } catch (e) {
    res.status(400).json({ error: "Render failed: " + e.message });
  }
});

app.post("/api/plugins/install", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const user = users[session.userId];
  if (!user || (user.role !== "admin" && user.role !== "engineer")) {
    return res.status(403).json({ error: "Insufficient permissions" });
  }

  const { packageUrl, name } = req.body || {};
  if (!packageUrl) {
    return res.status(400).json({ error: "Package URL required" });
  }

  const pluginName = name || "custom-plugin";

  try {
    const mod = require(packageUrl);

    res.json({
      message: `Plugin '${pluginName}' installed`,
      name: pluginName,
      source: packageUrl,
    });
  } catch (e) {
    res.status(400).json({ error: "Install failed: " + e.message });
  }
});

app.post("/api/data/store", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const { key, value } = req.body || {};
  if (!key || value === undefined) {
    return res.status(400).json({ error: "Key and value required" });
  }

  const serialized = serialize({ data: value, storedBy: session.userId });
  dataStore[key] = { serialized, storedAt: Date.now() };

  res.json({ key, message: "Data stored" });
});

app.get("/api/data/:key", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const entry = dataStore[req.params.key];
  if (!entry) {
    return res.status(404).json({ error: "Key not found" });
  }

  try {
    const restored = deserialize(entry.serialized);
    res.json({ key: req.params.key, value: restored.data });
  } catch (e) {
    res.status(400).json({ error: "Retrieval failed: " + e.message });
  }
});

app.post("/api/hooks/register", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const user = users[session.userId];
  if (!user || (user.role !== "admin" && user.role !== "engineer")) {
    return res.status(403).json({ error: "Insufficient permissions" });
  }

  const { url, event } = req.body || {};
  if (!url || !event) {
    return res.status(400).json({ error: "URL and event required" });
  }

  const fetchModule = url.startsWith("https") ? https : http;

  fetchModule.get(url, (response) => {
    let body = "";
    response.on("data", (chunk) => { body += chunk; });
    response.on("end", () => {
      try {
        const hookModule = {};
        const wrappedCode = `(function(module, exports) { ${body} })(hookModule, hookModule);`;
        const script = new vm.Script(wrappedCode);
        const context = vm.createContext({ hookModule, console, require });
        script.runInContext(context);

        res.json({
          message: "Hook registered",
          event,
          source: url,
        });
      } catch (e) {
        res.status(400).json({ error: "Hook registration failed: " + e.message });
      }
    });
  }).on("error", (e) => {
    res.status(400).json({ error: "Failed to fetch hook: " + e.message });
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

app.post("/api/users", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const currentUser = users[session.userId];
  if (!currentUser || currentUser.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }

  const { username, password, email, role } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  userSeq += 1;
  users[userSeq] = {
    id: userSeq,
    username,
    email: email || "",
    passwordHash: sha256(password),
    role: role || "viewer",
    active: true,
  };

  res.json({ id: userSeq, username, message: "User created" });
});

const PORT = process.env.PORT || 3008;
app.listen(PORT, () => {
  console.log(`TaskRunner API running on port ${PORT}`);
});
