const express = require("express");
const { exec, execSync, execFile } = require("child_process");
const path = require("path");

const app = express();
app.use(express.json());

const UPLOAD_DIR = process.env.UPLOAD_DIR || "/tmp/uploads";
const LOG_DIR = process.env.LOG_DIR || "/var/log/sysadmin";

app.get("/api/ping", (req, res) => {
  const host = req.query.host;
  if (!host) {
    return res.status(400).json({ error: "host parameter is required" });
  }
  exec("ping -c 3 " + host, { timeout: 10000 }, (err, stdout, stderr) => {
    if (err && !stdout) {
      return res.status(500).json({ error: stderr || err.message });
    }
    res.json({ host, output: stdout });
  });
});

app.get("/api/dns/lookup", (req, res) => {
  const domain = req.query.domain;
  const recordType = req.query.type || "A";

  if (!domain) {
    return res.status(400).json({ error: "domain parameter is required" });
  }

  const allowedTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
  const safeType = allowedTypes.includes(recordType) ? recordType : "A";

  const cmd = `dig ${safeType} ${domain} +short`;
  exec(cmd, { timeout: 10000 }, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: stderr || err.message });
    }
    res.json({ domain, type: safeType, result: stdout.trim() });
  });
});

function buildGrepCommand(keyword, logPath, contextLines) {
  const lines = parseInt(contextLines, 10) || 0;
  let cmd = `grep -n '${keyword}' ${logPath}`;
  if (lines > 0) {
    cmd = `grep -n -C ${lines} '${keyword}' ${logPath}`;
  }
  return cmd;
}

app.get("/api/logs/search", (req, res) => {
  const { keyword, file: logFile = "syslog", context = "0" } = req.query;

  if (!keyword) {
    return res.status(400).json({ error: "keyword parameter is required" });
  }

  const logPath = path.join(LOG_DIR, logFile);
  const cmd = buildGrepCommand(keyword, logPath, context);

  exec(cmd, { timeout: 15000 }, (err, stdout, stderr) => {
    if (err && err.code !== 1) {
      return res.status(500).json({ error: stderr || err.message });
    }
    const matches = stdout.trim() ? stdout.trim().split("\n") : [];
    res.json({ file: logFile, matches });
  });
});

app.get("/api/files/list", (req, res) => {
  const directory = req.query.path || UPLOAD_DIR;
  const pattern = req.query.pattern || "*";

  execFile("find", [directory, "-name", pattern, "-maxdepth", "2"], { timeout: 10000 },
    (err, stdout, stderr) => {
      if (err) {
        return res.status(500).json({ error: stderr || err.message });
      }
      const files = stdout.trim() ? stdout.trim().split("\n") : [];
      res.json({ directory, files });
    }
  );
});

function sanitizeFilename(name) {
  return name.replace(/[/\\]/g, "_");
}

app.post("/api/files/archive", (req, res) => {
  const { filePath, name = "archive" } = req.body;
  if (!filePath) {
    return res.status(400).json({ error: "filePath is required" });
  }

  const safeName = sanitizeFilename(name);
  const archivePath = `/tmp/${safeName}.tar.gz`;
  const cmd = `tar czf ${archivePath} ${filePath}`;

  exec(cmd, { timeout: 30000 }, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: stderr || err.message });
    }
    res.json({ archive: archivePath });
  });
});

app.get("/api/system/info", (req, res) => {
  try {
    const info = {
      hostname: execSync("hostname").toString().trim(),
      uptime: execSync("uptime -p").toString().trim(),
      kernel: execSync("uname -r").toString().trim(),
      disk: execSync("df -h /").toString().trim(),
    };
    res.json(info);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/network/check", (req, res) => {
  const { host, port } = req.body;
  if (!host || !port) {
    return res.status(400).json({ error: "host and port are required" });
  }

  const portNum = parseInt(port, 10);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    return res.status(400).json({ error: "Invalid port range" });
  }

  const cmd = `nc -zv -w 3 ${host} ${portNum}`;
  exec(cmd, { timeout: 10000 }, (err, stdout, stderr) => {
    const output = stderr || stdout;
    res.json({ host, port: portNum, result: output.trim() });
  });
});

app.post("/api/certs/check", (req, res) => {
  const { hostname, port = 443 } = req.body;
  if (!hostname) {
    return res.status(400).json({ error: "hostname is required" });
  }

  const cmd = `echo | openssl s_client -connect ${hostname}:${port} -servername ${hostname} 2>/dev/null | openssl x509 -noout -dates`;
  exec(cmd, { timeout: 15000 }, (err, stdout, stderr) => {
    if (err && !stdout) {
      return res.status(500).json({ error: "Failed to check certificate" });
    }
    res.json({ hostname, port, certificate: stdout.trim() });
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`SysAdmin API running on port ${PORT}`);
});
