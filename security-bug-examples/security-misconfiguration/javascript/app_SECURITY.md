# Security Companion Document: app.js

## Vulnerability: Overly Permissive CORS with Credential Support

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L13-L19  

### Description
The Express CORS middleware is configured with `origin: true`, which reflects any requesting origin, combined with `credentials: true`. This allows any website to make authenticated cross-origin requests to the API. The `allowedHeaders: ["*"]` further removes any header restrictions.

### Exploitation Scenario
An attacker hosts a page that makes `fetch()` requests with `credentials: 'include'` to the API. The server reflects the attacker's origin and allows credentials, so the browser sends the victim's cookies. The attacker reads product data, settings, or admin diagnostics from the victim's session.

### Remediation Guidance
Configure CORS with an explicit origin allowlist:
```javascript
app.use(cors({
  origin: ["https://app.acmecorp.io"],
  credentials: true,
  methods: ["GET", "POST", "PUT"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
```

### Complexity Rationale
This is rated Moderate because `origin: true` is a valid cors middleware option that appears functional. A reviewer must understand that reflecting arbitrary origins with credentials enabled defeats the same-origin policy.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the cors middleware configuration object and recognize that `origin: true` combined with `credentials: true` is a dangerous combination.

---

## Vulnerability: Server Version Information Disclosure via Headers

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L46-L49  

### Description
A middleware explicitly sets `X-Powered-By` and `Server` response headers to reveal the exact Express and Node.js versions. This information helps attackers identify known vulnerabilities in the specific framework and runtime versions.

### Exploitation Scenario
An attacker sends any request and inspects the response headers to learn the server runs `Express/4.18.2` on `Node.js/20.10.0`. The attacker searches CVE databases for known vulnerabilities in these exact versions and crafts targeted exploits.

### Remediation Guidance
Remove or suppress version-revealing headers:
```javascript
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.removeHeader("Server");
  next();
});
```

### Complexity Rationale
This is rated Obvious because the version strings are plaintext literals in a middleware function, immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match `setHeader("X-Powered-By", ...)` and `setHeader("Server", ...)` patterns with simple string matching.

---

## Vulnerability: XML External Entity (XXE) Processing in Product Import

**CWE:** CWE-611  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L82-L83  

### Description
The product import endpoint uses `libxmljs2.parseXml()` with `noent: true` and `nonet: false`, which enables external entity resolution and network access during XML parsing. This allows attackers to read local files or make server-side requests through crafted XML payloads.

### Exploitation Scenario
An attacker sends a POST to `/api/products/import` with:
```xml
<?xml version="1.0"?>
<!DOCTYPE products [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<products><product><name>&xxe;</name><sku>X</sku><price>0</price><stock>0</stock></product></products>
```
The server resolves the entity and returns the contents of `/etc/passwd` in the product name field.

### Remediation Guidance
Disable entity resolution in libxmljs2:
```javascript
const doc = libxmljs.parseXml(xmlData, { noent: false, nonet: true });
```

### Complexity Rationale
This is rated Moderate because the parser options are explicit but require understanding of what `noent` and `nonet` control in the context of XXE attacks.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools have well-known rules for detecting XXE-enabling parser configurations like `noent: true` in XML parsing libraries.

---

## Vulnerability: Verbose Error Responses with Stack Traces

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L155-L162  

### Description
The global error handler returns the error name, message, full stack trace, request path, and HTTP method in the JSON response. This information disclosure reveals internal file paths, module structure, and code flow to any client that triggers an error.

### Exploitation Scenario
An attacker sends malformed requests to trigger errors and collects stack traces. The traces reveal the application's directory structure, installed package versions, and internal function names, enabling targeted attacks against known vulnerabilities in the dependencies.

### Remediation Guidance
Log errors server-side and return generic messages:
```javascript
app.use((err, req, res, _next) => {
  console.error(err);
  return res.status(500).json({ error: "Internal server error" });
});
```

### Complexity Rationale
This is rated Moderate because error handlers that include stack traces are common during development. A reviewer must recognize that returning `err.stack` to clients is an information disclosure risk.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace `err.stack` into HTTP response bodies within Express error middleware.

---

## Vulnerability: Unrestricted Settings Modification Without Authentication

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L131-L137  

### Description
The `PUT /api/settings` endpoint accepts arbitrary key-value pairs and merges them into the settings object without authentication or input validation. Any unauthenticated user can modify security-critical settings including `tlsVerify`, `rateLimit`, `logLevel`, and `allowedOrigins`.

### Exploitation Scenario
An attacker sends `PUT /api/settings` with `{"tlsVerify": false, "rateLimit": 0, "logLevel": "error"}` to disable TLS verification, remove rate limiting, and suppress detailed logging. With security controls weakened, the attacker proceeds to exfiltrate data or brute-force credentials without detection.

### Remediation Guidance
Add authentication and restrict modifiable settings:
```javascript
const MUTABLE_SETTINGS = new Set(["maintenanceMode", "maxUploadSize"]);

app.put("/api/settings", (req, res) => {
  const token = req.headers["x-admin-token"] || "";
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  for (const [key, value] of Object.entries(req.body || {})) {
    if (MUTABLE_SETTINGS.has(key)) settings[key] = value;
  }
  return res.json({ message: "Settings updated", settings });
});
```

### Complexity Rationale
This is rated Nuanced because the endpoint looks like a standard CRUD operation. Recognizing the security impact requires understanding which settings are security controls and that the endpoint lacks authentication.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine which settings are security-critical or that the endpoint lacks authentication. This is a business logic flaw.

---

## Vulnerability: Diagnostics Endpoint Exposes Credentials and Environment Variables

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L139-L152  

### Description
The `/api/admin/diagnostics` endpoint returns the database host, username, and password, the complete `process.env` object (which may contain cloud credentials, API keys, and other secrets), Node.js version, memory usage, and uptime. While protected by a static admin token, the token is hardcoded in the source code.

### Exploitation Scenario
An attacker who discovers the hardcoded token `super-admin-token-2024` sends `GET /api/admin/diagnostics` and receives the database password `Pg_Pr0d#2024`, all environment variables, and system information. The attacker uses the database credentials for direct database access.

### Remediation Guidance
Remove sensitive data from diagnostic responses:
```javascript
app.get("/api/admin/diagnostics", (req, res) => {
  // ... auth check ...
  return res.json({
    productCount: Object.keys(products).length,
    uptime: process.uptime(),
    nodeVersion: process.version,
  });
});
```

### Complexity Rationale
This is rated Moderate because the endpoint is admin-protected, which may seem sufficient. A reviewer must recognize that exposing `process.env` and raw database credentials through any endpoint is excessive information disclosure.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect `process.env` being passed to `res.json()`, but the admin token check may cause tools to deprioritize the finding.
