# JavaScript Security Code Review Guide

## 1. Introduction

This guide provides a structured approach to security-focused code review for JavaScript and Node.js applications. It is designed for both beginners learning to identify security vulnerabilities in JavaScript code and experienced developers looking for a language-specific checklist to streamline their reviews.

JavaScript's dynamic typing, prototype-based inheritance, single-threaded event loop with async concurrency, and the vast npm ecosystem make it enormously productive — but these same qualities introduce security pitfalls that static analysis alone cannot always catch. This guide covers manual review strategies, common anti-patterns, recommended tooling, and vulnerability patterns organized by class, with cross-references to the intentionally vulnerable examples in this project.

**Audience:** Security trainees, application developers, code reviewers, and anyone evaluating JavaScript/Node.js codebases for security weaknesses.

---

## 2. Manual Review Best Practices

### 2.1 Trace Data from Entry to Sink

Express.js applications accept user input through `req.query`, `req.params`, `req.body`, `req.headers`, and `req.cookies`. Trace every external input to where it is consumed — database queries, shell commands, HTML output, HTTP requests, or file operations. Any path from source to sink without validation or sanitization is a potential vulnerability.

### 2.2 Inspect Template Literals and String Concatenation in Sensitive Contexts

JavaScript template literals (`` `...${expr}...` ``) and string concatenation are the primary vectors for injection. When any of these are used to build SQL queries, shell commands, HTML output, or URLs with user-controlled data, treat it as a high-priority finding.

### 2.3 Review require() and import Statements

Scan imports for modules known to introduce risk:
- `child_process` (`exec`, `execSync`, `spawn` with `shell: true`) — command injection
- `node-serialize` (`deserialize`) — arbitrary code execution via deserialization
- `vm` (`runInContext`, `runInNewContext`) — sandbox escape via prototype chain
- `eval`, `Function()` constructor — arbitrary code execution
- `fs` with user-controlled paths — path traversal and file-based TOCTOU
- `http`/`https` with user-controlled URLs — SSRF
- `crypto` with `createHash("md5")` or `createCipheriv("des-ecb", ...)` — weak cryptography

### 2.4 Check for Hardcoded Secrets

Search for string literals that look like passwords, API keys, tokens, or connection strings. Common patterns include variables named `MASTER_KEY`, `API_KEY`, `SECRET`, `PASSWORD`, `TOKEN`, or connection strings containing `://user:pass@host`. Also look for hardcoded backdoor codes and static admin tokens.

### 2.5 Examine Error Handling

Look for Express error handlers that return `err.stack`, `err.message`, or raw exception details to the caller. Check for `catch` blocks that include database credentials, file paths, or environment variables in the response. In Express, check global error middleware for verbose responses.

### 2.6 Evaluate Cryptographic Choices

Flag uses of `crypto.createHash("md5")` or `crypto.createHash("sha1")` for password hashing. Check for `des-ecb` or other deprecated ciphers in `createCipheriv`. Verify that `Math.random()` or custom LCG/PRNG implementations are not used for security-sensitive token generation — use `crypto.randomBytes()` instead.

### 2.7 Assess Access Control Logic

For every Express route, verify:
- Authentication is checked before any business logic executes
- Authorization checks use server-side session data, not client-supplied headers (e.g., `x-user-role`)
- Object-level access control prevents users from accessing resources belonging to others (IDOR)
- Debug and diagnostic endpoints are not exposed without authentication

### 2.8 Review Configuration and Middleware

Check Express middleware configuration for:
- `cors({ origin: true, credentials: true })` — overly permissive CORS
- Missing `helmet()` or equivalent security headers
- `x-powered-by` header not disabled
- XML parsers with `noent: true` or entity resolution enabled (XXE)
- Settings endpoints that accept arbitrary key-value pairs without authentication

### 2.9 Understand Async Concurrency

JavaScript's event loop means `await` yields control. When shared mutable state is read, awaited, then written, other async tasks can interleave. Look for check-then-act patterns separated by `await` in `Promise.all` contexts — these are async race conditions even though Node.js is single-threaded.

---

## 3. Common Security Pitfalls

### 3.1 Injection

| Anti-Pattern | Risk |
|---|---|
| `` `SELECT * FROM t WHERE x = '${userInput}'` `` | SQL injection via template literal |
| `applyFilters()` building SQL fragments with template literals | SQL injection via helper function |
| Unvalidated `order` parameter in `ORDER BY ${sort} ${order}` | ORDER BY clause injection |
| Dynamic column names from `req.query.fields` in SELECT clause | SELECT clause injection |
| `exec("ping -c 3 " + host)` | Command injection via `child_process.exec` |
| `` exec(`dig ${type} ${domain} +short`) `` | Command injection via template literal in exec |
| `exec` with single-quote wrapping as pseudo-sanitization | Command injection bypass |
| Template literal interpolation into HTML response strings | Reflected and stored XSS |
| JSONP callback without validation | XSS via callback parameter |
| User input in `<script>` block JavaScript string literals | JavaScript context XSS |

### 3.2 Broken Access Control

| Anti-Pattern | Risk |
|---|---|
| Endpoint returns full user record (including SSN, salary) without auth | Excessive data exposure |
| Authorization reads role from `x-user-role` header instead of session | Client-side role spoofing |
| No ownership check on invoice/document access | IDOR — any authenticated user can read any resource |
| Role update endpoint with no admin-only restriction | Privilege escalation |
| Debug/config endpoints with no authentication | Information disclosure of secrets |

### 3.3 Cryptographic Failures

| Anti-Pattern | Risk |
|---|---|
| `crypto.createCipheriv("des-ecb", key, null)` | Deprecated cipher in insecure mode |
| `Buffer.from("s3cr3t!!", "utf8")` as encryption key | Hardcoded key in source code |
| `crypto.createHash("md5").update(password)` for password storage | Weak, unsalted password hashing |
| MD5 concatenation for data integrity signatures | Collision-vulnerable integrity check |
| Custom LCG PRNG seeded with `userId * 1000 + Date.now()` | Predictable session tokens |
| SHA-1 hash of sequential counter + timestamp for API tokens | Predictable API tokens |

### 3.4 Insecure Design

| Anti-Pattern | Risk |
|---|---|
| Plaintext passwords and credentials as module-level constants | Credential exposure in source code |
| `err.stack` and database credentials returned in error responses | Stack trace and credential leakage |
| Debug endpoint returning full user objects including passwords | Sensitive data exposure |
| Password reset token returned in API response body | Token leakage bypassing email verification |
| Config endpoint exposing infrastructure credentials | Credential transmission over network |

### 3.5 Security Misconfiguration

| Anti-Pattern | Risk |
|---|---|
| `cors({ origin: true, credentials: true })` | Overly permissive CORS |
| `res.setHeader("X-Powered-By", "Express/4.18.2")` | Server version disclosure |
| `libxmljs.parseXml(data, { noent: true, nonet: false })` | XXE via XML entity resolution |
| Global error handler returning `err.stack` | Information disclosure |
| Settings endpoint accepting arbitrary updates without auth | Security control manipulation |
| Diagnostics endpoint exposing `process.env` | Environment variable leakage |

### 3.6 Vulnerable Components

| Anti-Pattern | Risk |
|---|---|
| `_.merge()` with user input on lodash < 4.17.21 | Prototype pollution |
| `ejs.render(userTemplate)` on ejs < 3.1.7 | Server-side template injection |
| Outdated Express, axios, marked versions in `package.json` | Known CVEs in dependencies |
| `node-serialize` `deserialize()` on any version | Arbitrary code execution |

### 3.7 Authentication Failures

| Anti-Pattern | Risk |
|---|---|
| Hardcoded `MASTER_KEY` used as password and API key bypass | Backdoor authentication |
| `SUPPORT_BACKDOOR` code enabling user impersonation | Hidden impersonation endpoint |
| MD5 for password hashing in auth flow | Weak credential storage |
| No rate limiting on login endpoint | Brute-force and credential stuffing |

### 3.8 Integrity Failures (Deserialization)

| Anti-Pattern | Risk |
|---|---|
| `node-serialize.deserialize(userInput)` | Arbitrary code execution via IIFE pattern |
| `require(userSuppliedPath)` | Arbitrary module loading |
| `vm.runInContext()` with user-controlled code | VM sandbox escape via prototype chain |
| Fetching remote JS and executing via `vm.Script` with `require` in context | Remote code execution |

### 3.9 Logging and Monitoring Failures

| Anti-Pattern | Risk |
|---|---|
| Login response includes `password` and `api_key` fields | Credential leakage in responses |
| No logging of failed or successful authentication attempts | Brute-force attacks go undetected |
| No audit logging for role changes or privilege escalation | Unauthorized changes are invisible |
| Financial transactions with no audit trail | Fraud goes undetected |
| Data export endpoint with no logging | Mass exfiltration undetected |
| API key regeneration and MFA toggle with no logging | Security config changes invisible |

### 3.10 SSRF

| Anti-Pattern | Risk |
|---|---|
| `http.get(userUrl)` without any validation | Unrestricted SSRF |
| Blocklist checking only `localhost` and `127.0.0.1` | SSRF blocklist bypass via `[::1]`, `0.0.0.0`, etc. |
| Webhook callback URLs not re-validated at delivery time | Two-step SSRF |
| Hostname string check instead of resolved IP check | DNS rebinding bypass |
| Service proxy with user-supplied `baseUrl` fallback | Open relay to internal services |

### 3.11 Race Conditions

| Anti-Pattern | Risk |
|---|---|
| Read-await-write on `this.balance` in `Promise.all` context | Lost deposits / double-spend |
| Check `balance >= amount`, await, then subtract | Overdraw via async TOCTOU |
| `available > 0` check, await, then decrement | Ticket overselling |
| `readFileSync` → increment → `writeFileSync` without file lock | Lost counter updates |
| Async singleton with `await` between null check and assignment | Multiple singleton instances |

---

## 4. Recommended SAST Tools & Linters

### 4.1 eslint-plugin-security

eslint-plugin-security is an ESLint plugin that identifies potential security hotspots in JavaScript and Node.js code, including dangerous function calls, regex patterns, and non-literal arguments.

**Installation:**

```bash
npm install --save-dev eslint eslint-plugin-security
```

**Create or update `.eslintrc.json`:**

```json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}
```

**Scan a single file:**

```bash
npx eslint --plugin security --rule '{"security/detect-child-process": "error", "security/detect-eval-with-expression": "error", "security/detect-non-literal-require": "error", "security/detect-non-literal-fs-filename": "error", "security/detect-object-injection": "warn"}' injection/sql-injection/javascript/app.js
```

**Scan an entire directory:**

```bash
npx eslint --ext .js security-bug-examples/
```

**What eslint-plugin-security catches:** `child_process.exec()` with non-literal arguments, `eval()` with expressions, non-literal `require()`, non-literal `fs` filenames, `Buffer()` constructor misuse, `RegExp()` with user input (ReDoS), object bracket notation injection, and `new Function()` calls.

### 4.2 NodeJsScan

NodeJsScan is a static security code scanner for Node.js applications that identifies security vulnerabilities using pattern matching and semantic analysis.

**Installation:**

```bash
pip install nodejsscan
```

**Scan a single file:**

```bash
nodejsscan -f injection/command-injection/javascript/app.js
```

**Scan a directory:**

```bash
nodejsscan -d security-bug-examples/
```

**Generate a JSON report:**

```bash
nodejsscan -d security-bug-examples/ -o nodejsscan_report.json
```

**What NodeJsScan catches:** Command injection via `exec`/`spawn`, SQL injection, XSS patterns, hardcoded secrets, insecure cryptography, `eval`/`Function` usage, insecure random number generation, directory traversal, SSRF patterns, and insecure deserialization.

### 4.3 Semgrep

Semgrep is a multi-language static analysis tool with pattern-based rules. It supports custom rules and has a large community rule registry with extensive JavaScript/Node.js coverage.

**Installation:**

```bash
pip install semgrep
# or
brew install semgrep
```

**Scan with the default JavaScript security ruleset:**

```bash
semgrep --config "p/javascript" security-bug-examples/
```

**Scan with Node.js-specific rules:**

```bash
semgrep --config "p/nodejs" security-bug-examples/
```

**Scan with OWASP Top 10 rules:**

```bash
semgrep --config "p/owasp-top-ten" security-bug-examples/
```

**Scan a single file:**

```bash
semgrep --config "p/javascript" injection/sql-injection/javascript/app.js
```

**Run with auto configuration (recommended for first-time scans):**

```bash
semgrep --config auto security-bug-examples/
```

**What Semgrep catches:** SQL injection via template literals and concatenation, command injection through `child_process`, XSS in Express responses, insecure deserialization, SSRF patterns, hardcoded secrets, weak cryptography, prototype pollution via `_.merge`, and many framework-specific issues. Semgrep's pattern matching is particularly effective at detecting template-literal-based injection that eslint-plugin-security may miss.

---

## 5. Language-Specific Vulnerability Patterns

### 5.1 SQL Injection (CWE-89)

**Pattern: Template literal in query construction**

```javascript
// Vulnerable — user input interpolated directly into SQL
const sql = `SELECT * FROM products WHERE name LIKE '%${keyword}%'`;
const rows = db.prepare(sql).all();
```

**Pattern: Helper function building SQL fragments with template literals**

```javascript
// Vulnerable — filter values embedded via template literal
function applyFilters(baseQuery, params, filters) {
  if (filters.status) {
    clauses.push(`o.status = '${filters.status}'`);
  }
}
```

**Pattern: Unvalidated ORDER BY direction**

```javascript
// Vulnerable — sort column validated but order direction is not
const sql = `SELECT * FROM products ORDER BY ${column} ${order}`;
```

**Pattern: Dynamic column names in SELECT clause**

```javascript
// Vulnerable — user-supplied field names interpolated into SELECT
const columnList = fields.split(",").map(f => f.trim()).join(", ");
const sql = `SELECT ${columnList} FROM products`;
```

**Safe alternative:**

```javascript
const sql = "SELECT * FROM products WHERE name LIKE ?";
const rows = db.prepare(sql).all("%" + keyword + "%");
```

### 5.2 Command Injection (CWE-78)

**Pattern: `exec()` with string concatenation**

```javascript
const { exec } = require("child_process");
exec("ping -c 3 " + host, (err, stdout) => { /* ... */ });
```

**Pattern: `exec()` with template literal**

```javascript
exec(`dig ${recordType} ${domain} +short`, (err, stdout) => { /* ... */ });
```

**Pattern: Pseudo-sanitization with single quotes**

```javascript
// Vulnerable — single quotes do not prevent injection
const cmd = `grep -n '${keyword}' ${logPath}`;
exec(cmd, (err, stdout) => { /* ... */ });
```

**Pattern: Complex shell pipeline with multiple interpolation points**

```javascript
// Vulnerable — hostname interpolated into multi-stage pipeline
const cmd = `echo | openssl s_client -connect ${hostname}:443 -servername ${hostname} 2>/dev/null | openssl x509 -noout -dates`;
exec(cmd, (err, stdout) => { /* ... */ });
```

**Safe alternative:**

```javascript
const { execFile } = require("child_process");
execFile("ping", ["-c", "3", host], { timeout: 10000 }, (err, stdout) => {
  res.json({ host, output: stdout });
});
```

### 5.3 Cross-Site Scripting — XSS (CWE-79)

**Pattern: Template literal interpolation into HTML**

```javascript
// Vulnerable — post content rendered without escaping
page += `<h2>${post.title}</h2>`;
page += `<div>${post.content}</div>`;
```

**Pattern: Reflected XSS in search results**

```javascript
// Vulnerable — query reflected back into page
page += `<p>Results for: <em>${q}</em></p>`;
```

**Pattern: Attribute injection via unescaped value**

```javascript
// Vulnerable — breaks out of attribute context
page += `<input type="text" name="q" value="${q}">`;
```

**Pattern: JavaScript context injection in server-rendered script blocks**

```javascript
// Vulnerable — user input in JS string literal
page += `<script>var config = { theme: "${theme}", title: "${title}" };</script>`;
```

**Pattern: JSONP callback injection**

```javascript
// Vulnerable — callback not validated
const jsonp = `${callback}(${JSON.stringify(data)})`;
res.type("application/javascript").send(jsonp);
```

**Safe alternative:**

```javascript
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
page += `<h2>${escapeHtml(post.title)}</h2>`;
```

### 5.4 Broken Access Control (CWE-200, CWE-284, CWE-639)

**Pattern: No authentication on sensitive endpoint**

```javascript
app.get("/api/users/:id", (req, res) => {
  const user = users[parseInt(req.params.id, 10)];
  res.json(user); // Returns SSN, salary — no auth check
});
```

**Pattern: Client-controlled authorization header**

```javascript
const role = req.headers["x-user-role"] || "employee";
if (role !== "admin") {
  return res.status(403).json({ error: "Admin access required" });
}
```

**Pattern: Missing object-level authorization (IDOR)**

```javascript
// Any authenticated user can access any invoice — no ownership check
const invoice = invoices[parseInt(req.params.id, 10)];
return res.json(invoice);
```

### 5.5 Cryptographic Failures (CWE-327, CWE-328, CWE-330)

**Pattern: DES in ECB mode with hardcoded key**

```javascript
const KEY = Buffer.from("s3cr3t!!", "utf8");
const cipher = crypto.createCipheriv("des-ecb", KEY, null);
```

**Pattern: MD5 for password hashing**

```javascript
function md5(str) {
  return crypto.createHash("md5").update(str).digest("hex");
}
```

**Pattern: Custom LCG PRNG for session tokens**

```javascript
// Vulnerable — predictable seed and weak algorithm
let seed = userId * 1000 + Math.floor(Date.now() / 1000);
function lcg() {
  seed = (seed * 1664525 + 1013904223) & 0xffffffff;
  return (seed >>> 0) / 0xffffffff;
}
```

**Safe alternative:**

```javascript
const bcrypt = require("bcrypt");
const hash = await bcrypt.hash(password, 12);

const token = crypto.randomBytes(32).toString("hex");
```

### 5.6 Insecure Design (CWE-209, CWE-522)

**Pattern: Hardcoded credentials as module constants**

```javascript
const DB_PASS = "Pg_Pr0d#2024";
const SMTP_PASS = "SmtpR3lay#2024!";
```

**Pattern: Stack trace and credentials in error response**

```javascript
return res.status(500).json({
  error: err.message,
  trace: err.stack,
  database: { host: DB_HOST, user: DB_USER, password: DB_PASS },
});
```

**Pattern: Password reset token returned in response**

```javascript
return res.json({
  message: "Reset email sent",
  token: resetToken,        // Should only be sent via email
  smtpServer: SMTP_HOST,    // Internal infrastructure exposed
});
```

### 5.7 Security Misconfiguration (CWE-16, CWE-611)

**Pattern: XXE via libxmljs2 with entity resolution**

```javascript
const doc = libxmljs.parseXml(xmlData, { noent: true, nonet: false });
```

**Pattern: Overly permissive CORS**

```javascript
app.use(cors({
  origin: true,           // Reflects any origin
  credentials: true,      // Allows cookies
  allowedHeaders: ["*"],  // No header restrictions
}));
```

**Pattern: Version disclosure via headers**

```javascript
res.setHeader("X-Powered-By", "Express/4.18.2");
res.setHeader("Server", "Node.js/20.10.0");
```

### 5.8 Vulnerable and Outdated Components (CWE-1104)

**Pattern: Prototype pollution via lodash merge**

```javascript
const _ = require("lodash"); // 4.17.20 — vulnerable
_.merge(product, importedData); // __proto__ pollution
```

**Pattern: Server-side template injection via outdated EJS**

```javascript
const ejs = require("ejs"); // 3.1.5 — CVE-2022-29078
const html = ejs.render(userTemplate, data);
```

**Pattern: Unsafe deserialization via node-serialize**

```javascript
const serialize = require("node-serialize");
const obj = serialize.deserialize(userInput); // RCE via _$ND_FUNC$_
```

### 5.9 Integrity Failures — Deserialization (CWE-502, CWE-829)

**Pattern: node-serialize deserialization of untrusted data**

```javascript
const { deserialize } = require("node-serialize");
const jobData = deserialize(payload); // Executes embedded functions
```

**Pattern: Dynamic require() with user input**

```javascript
const mod = require(packageUrl); // packageUrl from request body
```

**Pattern: VM sandbox escape via prototype chain**

```javascript
const ctx = vm.createContext({ data: variables });
const code = `\`${templateBody}\``;
const result = vm.runInContext(code, ctx); // Escapable via constructor chain
```

**Pattern: Remote code execution via fetched script**

```javascript
const response = await fetch(hookUrl);
const code = await response.text();
const script = new vm.Script(`(function(require, console) { ${code} })`);
script.runInContext(vm.createContext({ require, console }));
```

### 5.10 Logging and Monitoring Failures (CWE-778)

**Pattern: No logging in authentication flow**

```javascript
app.post("/api/login", (req, res) => {
  // No console.log, no winston, no morgan — zero logging
  if (!user || md5(password) !== user.passwordHash) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  // Successful login also not logged
});
```

**Pattern: Credentials returned in login response**

```javascript
return res.json({
  token: sessionToken,
  password: user.password,   // Plaintext password leaked
  api_key: user.apiKey,      // API key leaked
});
```

**Pattern: No audit trail for privilege changes**

```javascript
target.role = newRole; // Role changed with no log entry
return res.json({ message: "Role updated" });
```

### 5.11 SSRF (CWE-918)

**Pattern: Unrestricted URL fetch**

```javascript
const url = req.body.url;
http.get(url, (response) => { /* ... */ });
```

**Pattern: Incomplete blocklist**

```javascript
const blocked = ["localhost", "127.0.0.1"];
// Missing: 0.0.0.0, [::1], 169.254.x.x, 10.x.x.x, decimal IPs
```

**Pattern: Service proxy with user-supplied base URL fallback**

```javascript
let base = serviceMap[service] || req.query.baseUrl || "";
const fullUrl = base + path;
http.get(fullUrl, (response) => { /* ... */ });
```

**Pattern: Hostname string check vulnerable to DNS rebinding**

```javascript
// Vulnerable — checks hostname string, not resolved IP
if (parsed.hostname.startsWith("169.254")) {
  return res.status(403).json({ error: "Blocked" });
}
// Attacker uses DNS rebinding to resolve to 169.254.169.254 after check
```

**Safe alternative:**

```javascript
const dns = require("dns").promises;
const addresses = await dns.resolve4(parsed.hostname);
for (const addr of addresses) {
  if (addr.startsWith("127.") || addr.startsWith("10.") || addr.startsWith("169.254.")) {
    return res.status(403).json({ error: "Blocked host" });
  }
}
```

### 5.12 Race Conditions (CWE-362)

**Pattern: Async check-then-act without serialization**

```javascript
async withdraw(amount) {
  if (this.balance >= amount) {
    await new Promise(resolve => setImmediate(resolve)); // Yields event loop
    this.balance -= amount; // Another task may have changed balance
  }
}
```

**Pattern: Read-await-write on shared state in Promise.all**

```javascript
async deposit(amount) {
  const current = this.balance;
  await new Promise(resolve => setImmediate(resolve));
  this.balance = current + amount; // Stale read — lost update
}
```

**Pattern: File-based TOCTOU without locking**

```javascript
let count = parseInt(fs.readFileSync(filepath, "utf8"), 10);
count++;
fs.writeFileSync(filepath, String(count)); // Lost update if concurrent
```

**Pattern: Async singleton initialization race**

```javascript
async function getConfig() {
  if (!configInstance) {
    await new Promise(resolve => setImmediate(resolve));
    configInstance = { settings: {} }; // Multiple instances created
  }
  return configInstance;
}
```

**Safe alternative:**

```javascript
const { Mutex } = require("async-mutex");
const mutex = new Mutex();

async function withdraw(amount) {
  const release = await mutex.acquire();
  try {
    if (this.balance >= amount) {
      this.balance -= amount;
      return true;
    }
    return false;
  } finally {
    release();
  }
}
```

---

## 6. Cross-References to Examples

The table below maps each vulnerability class to the JavaScript source file and companion documentation in this project. All paths are relative to the `docs/` directory.

| Vulnerability Class | Source File | Companion Doc |
|---|---|---|
| SQL Injection (CWE-89) | [`../injection/sql-injection/javascript/app.js`](../injection/sql-injection/javascript/app.js) | [`../injection/sql-injection/javascript/app_SECURITY.md`](../injection/sql-injection/javascript/app_SECURITY.md) |
| Command Injection (CWE-78) | [`../injection/command-injection/javascript/app.js`](../injection/command-injection/javascript/app.js) | [`../injection/command-injection/javascript/app_SECURITY.md`](../injection/command-injection/javascript/app_SECURITY.md) |
| Cross-Site Scripting (CWE-79) | [`../injection/xss/javascript/app.js`](../injection/xss/javascript/app.js) | [`../injection/xss/javascript/app_SECURITY.md`](../injection/xss/javascript/app_SECURITY.md) |
| Broken Access Control (CWE-200, CWE-284, CWE-639) | [`../broken-access-control/javascript/app.js`](../broken-access-control/javascript/app.js) | [`../broken-access-control/javascript/app_SECURITY.md`](../broken-access-control/javascript/app_SECURITY.md) |
| Cryptographic Failures (CWE-327, CWE-328, CWE-330) | [`../cryptographic-failures/javascript/app.js`](../cryptographic-failures/javascript/app.js) | [`../cryptographic-failures/javascript/app_SECURITY.md`](../cryptographic-failures/javascript/app_SECURITY.md) |
| Insecure Design (CWE-209, CWE-522) | [`../insecure-design/javascript/app.js`](../insecure-design/javascript/app.js) | [`../insecure-design/javascript/app_SECURITY.md`](../insecure-design/javascript/app_SECURITY.md) |
| Security Misconfiguration (CWE-16, CWE-611) | [`../security-misconfiguration/javascript/app.js`](../security-misconfiguration/javascript/app.js) | [`../security-misconfiguration/javascript/app_SECURITY.md`](../security-misconfiguration/javascript/app_SECURITY.md) |
| Vulnerable Components (CWE-1104) | [`../vulnerable-components/javascript/app.js`](../vulnerable-components/javascript/app.js) | [`../vulnerable-components/javascript/app_SECURITY.md`](../vulnerable-components/javascript/app_SECURITY.md) |
| Auth Failures (CWE-287, CWE-307, CWE-798) | [`../auth-failures/javascript/app.js`](../auth-failures/javascript/app.js) | [`../auth-failures/javascript/app_SECURITY.md`](../auth-failures/javascript/app_SECURITY.md) |
| Integrity Failures (CWE-502, CWE-829) | [`../integrity-failures/javascript/app.js`](../integrity-failures/javascript/app.js) | [`../integrity-failures/javascript/app_SECURITY.md`](../integrity-failures/javascript/app_SECURITY.md) |
| Logging/Monitoring Failures (CWE-778) | [`../logging-monitoring-failures/javascript/app.js`](../logging-monitoring-failures/javascript/app.js) | [`../logging-monitoring-failures/javascript/app_SECURITY.md`](../logging-monitoring-failures/javascript/app_SECURITY.md) |
| SSRF (CWE-918) | [`../ssrf/javascript/app.js`](../ssrf/javascript/app.js) | [`../ssrf/javascript/app_SECURITY.md`](../ssrf/javascript/app_SECURITY.md) |
| Race Condition (CWE-362) | [`../race-condition/javascript/app.js`](../race-condition/javascript/app.js) | [`../race-condition/javascript/app_SECURITY.md`](../race-condition/javascript/app_SECURITY.md) |

---

## 7. Quick-Reference Checklist

Use this checklist during JavaScript/Node.js code reviews. Each item maps to a vulnerability class covered in this guide.

- [ ] **Input validation** — All user inputs (`req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies`) are validated and sanitized before use in SQL, shell commands, HTML, or URLs
- [ ] **Parameterized queries** — All SQL queries use parameterized statements (`?` placeholders), never template literals or string concatenation
- [ ] **No exec with user input** — `child_process.exec()` and `execSync()` are not used with user-controlled data; use `execFile()` with argument arrays instead
- [ ] **Output encoding** — All user-controlled data rendered in HTML is escaped; context-specific escaping is used for HTML attributes, JavaScript strings, and URLs
- [ ] **JSONP validation** — JSONP callback parameters are validated against `^[a-zA-Z_$][a-zA-Z0-9_$]*$` or JSONP is replaced with CORS
- [ ] **Authentication on every endpoint** — All sensitive endpoints verify the session/token before processing; debug and diagnostic endpoints are protected
- [ ] **Server-side authorization** — Role and permission checks use server-side session data, not client-supplied headers like `x-user-role`
- [ ] **Object-level access control** — Resource access verifies the requesting user owns or is authorized for the specific resource
- [ ] **Strong password hashing** — Passwords are hashed with `bcrypt` or `argon2` — never `crypto.createHash("md5")` or `sha1`
- [ ] **Modern encryption** — AES-256-GCM is used; no DES, no ECB mode, no hardcoded keys
- [ ] **Cryptographic randomness** — Tokens and secrets use `crypto.randomBytes()`, not `Math.random()` or custom PRNGs
- [ ] **No hardcoded secrets** — API keys, passwords, encryption keys, and backdoor codes are loaded from environment variables or a secrets manager
- [ ] **Safe deserialization** — `node-serialize` is never used with untrusted data; use `JSON.parse()` for data interchange
- [ ] **No eval/Function** — `eval()`, `new Function()`, and `vm.runInContext()` are not used with user-controlled input
- [ ] **No dynamic require** — `require()` is not called with user-controlled paths; use an allowlist of known modules
- [ ] **SSRF protection** — Outbound HTTP requests validate URLs against an allowlist; resolved IPs are checked against internal/metadata ranges
- [ ] **Minimal error responses** — Error responses do not include stack traces, database credentials, or internal configuration
- [ ] **Secure CORS** — `cors()` is configured with explicit origin allowlist, not `origin: true` with `credentials: true`
- [ ] **No version disclosure** — `x-powered-by` is disabled; `Server` header does not reveal framework or runtime versions
- [ ] **XXE prevention** — XML parsers use `noent: false` and `nonet: true`
- [ ] **Audit logging** — Authentication events, privilege changes, financial transactions, and data exports are logged
- [ ] **No credentials in responses** — API responses do not include passwords, API keys, or other secrets
- [ ] **Async race protection** — Shared mutable state accessed across `await` boundaries uses `async-mutex` or equivalent serialization
- [ ] **File locking** — File-based read-modify-write operations use `proper-lockfile` or equivalent
- [ ] **Dependency hygiene** — `package.json` pins versions; dependencies are checked for known CVEs with `npm audit`
- [ ] **Rate limiting** — Authentication endpoints use `express-rate-limit` or equivalent to prevent brute-force attacks
