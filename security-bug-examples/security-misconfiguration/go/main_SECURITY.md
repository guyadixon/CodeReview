# Security Companion Document: main.go

## Vulnerability: Overly Permissive CORS with Origin Reflection and Credentials

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L97-L108  

### Description
The CORS middleware reflects the request's `Origin` header directly into the `Access-Control-Allow-Origin` response header (falling back to `*`) while setting `Access-Control-Allow-Credentials` to `true`. This allows any website to make authenticated cross-origin requests. The wildcard `*` for `Access-Control-Allow-Headers` removes header restrictions.

### Exploitation Scenario
An attacker hosts a malicious page that makes `fetch()` requests with `credentials: 'include'` to the API. The server reflects the attacker's origin and allows credentials, so the browser sends the victim's cookies. The attacker reads product data, settings, or admin diagnostics from the victim's session.

### Remediation Guidance
Validate the Origin header against an explicit allowlist:
```go
func corsMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        allowed := map[string]bool{"https://app.acmecorp.io": true}
        origin := c.GetHeader("Origin")
        if allowed[origin] {
            c.Header("Access-Control-Allow-Origin", origin)
            c.Header("Access-Control-Allow-Credentials", "true")
        }
        c.Header("Access-Control-Allow-Methods", "GET, POST, PUT")
        c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        c.Next()
    }
}
```

### Complexity Rationale
This is rated Moderate because the CORS middleware follows a common Gin pattern. A reviewer must understand that reflecting arbitrary origins with credentials enabled defeats the same-origin policy.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the `Origin` header value into the `Access-Control-Allow-Origin` response header and recognize the combination with `Allow-Credentials: true`.

---

## Vulnerability: Gin Debug Mode with Server Version Disclosure

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L86-L87  

### Description
The Gin framework is set to `DebugMode`, which enables verbose logging of all routes and request details. Additionally, the server header middleware explicitly reveals the Go runtime version and Gin framework version in every response via `Server` and `X-Powered-By` headers.

### Exploitation Scenario
An attacker inspects response headers to learn the exact Go and Gin versions. Debug mode logging may also expose request details in server logs accessible through other vulnerabilities. The attacker searches CVE databases for known vulnerabilities in the identified versions.

### Remediation Guidance
Set Gin to release mode and remove version headers:
```go
gin.SetMode(gin.ReleaseMode)

func serverHeaderMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("Server", "")
        c.Next()
    }
}
```

### Complexity Rationale
This is rated Obvious because `gin.SetMode(gin.DebugMode)` and the version string headers are plaintext values immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match `gin.DebugMode` and `X-Powered-By` header patterns through simple string matching.

---

## Vulnerability: Relaxed XML Parser Configuration

**CWE:** CWE-611  
**OWASP:** A05  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L180-L181  

### Description
The product import endpoint creates an XML decoder with `Strict = false`, which disables strict XML parsing. While Go's `encoding/xml` does not support external entity resolution, disabling strict mode allows malformed and non-standard XML to be processed. This is a defense-in-depth failure: the relaxed parser accepts input that should be rejected, and if the XML processing is ever migrated to a library that does support entities (e.g., a CGo wrapper around libxml2), the lack of strict parsing would compound the risk.

### Exploitation Scenario
An attacker sends non-standard XML with unexpected element structures or encoding tricks that bypass input validation. The relaxed parser accepts the malformed input, potentially leading to data corruption in the product catalog. If the XML library is later changed to one supporting external entities, the relaxed configuration provides no defense against XXE.

### Remediation Guidance
Enable strict XML parsing:
```go
decoder := xml.NewDecoder(strings.NewReader(string(rawXML)))
decoder.Strict = true
```

### Complexity Rationale
This is rated Nuanced because Go's `encoding/xml` is safe from XXE by default, and `Strict = false` appears to be a convenience setting. Recognizing this as a security misconfiguration requires understanding defense-in-depth principles and the risk of library changes.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would see Go's `encoding/xml` (which is safe from XXE) and not flag `Strict = false` as a security issue. The vulnerability is a defense-in-depth concern rather than an immediately exploitable flaw.

---

## Vulnerability: Verbose Error Responses with Stack Traces

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L172-L178  

### Description
The XML product import error handler returns `debug.Stack()` as a string in the JSON error response, along with the raw error message. This reveals internal goroutine state, file paths, and function names to any client that sends malformed XML.

### Exploitation Scenario
An attacker sends malformed XML to `/api/products/import` and receives a response containing the full Go stack trace. The trace reveals the application's module path, internal function names, and Go runtime version, enabling targeted attacks.

### Remediation Guidance
Log stack traces server-side and return generic errors:
```go
if err := decoder.Decode(&xmlProds); err != nil {
    log.Printf("XML parsing failed: %v\n%s", err, debug.Stack())
    c.JSON(http.StatusBadRequest, gin.H{"error": "XML parsing failed"})
    return
}
```

### Complexity Rationale
This is rated Moderate because including `debug.Stack()` in error responses is a common debugging pattern. A reviewer must recognize that returning stack traces to API clients is an information disclosure risk.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace `debug.Stack()` output into HTTP response bodies within Gin handlers.

---

## Vulnerability: Unrestricted Settings Modification Without Authentication

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L207-L218  

### Description
The `PUT /api/settings` endpoint accepts arbitrary key-value pairs and merges them into the settings map without authentication or input validation. Any unauthenticated user can modify security-critical settings including `tls_verify`, `rate_limit`, `log_level`, and `allowed_origins`.

### Exploitation Scenario
An attacker sends `PUT /api/settings` with `{"tls_verify": false, "rate_limit": 0, "log_level": "CRITICAL"}` to disable TLS verification, remove rate limiting, and suppress logging. The attacker then exfiltrates data or brute-forces credentials without detection.

### Remediation Guidance
Add authentication and restrict modifiable settings:
```go
func updateSettings(c *gin.Context) {
    token := c.GetHeader("X-Admin-Token")
    if token != adminToken {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    allowed := map[string]bool{"maintenance_mode": true, "max_upload_size": true}
    var body map[string]interface{}
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Request body required"})
        return
    }
    settingsMu.Lock()
    for k, v := range body {
        if allowed[k] { settings[k] = v }
    }
    settingsMu.Unlock()
    c.JSON(http.StatusOK, gin.H{"message": "Settings updated", "settings": settings})
}
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
**Affected Lines:** L220-L241  

### Description
The `/api/admin/diagnostics` endpoint returns the database host, username, and password, the complete set of environment variables (via `os.Environ()`), Go version, CPU count, and goroutine count. While protected by a static admin token, the token is hardcoded in the source code.

### Exploitation Scenario
An attacker who discovers the hardcoded token `super-admin-token-2024` sends `GET /api/admin/diagnostics` and receives the database password `Pg_Pr0d#2024`, all environment variables (potentially including cloud credentials), and system information. The attacker uses the database credentials for direct access.

### Remediation Guidance
Remove sensitive data from diagnostic responses:
```go
c.JSON(http.StatusOK, gin.H{
    "product_count": len(products),
    "go_version":    runtime.Version(),
    "goroutines":    runtime.NumGoroutine(),
})
```

### Complexity Rationale
This is rated Moderate because the endpoint is admin-protected, which may seem sufficient. A reviewer must recognize that exposing `os.Environ()` and raw database credentials through any endpoint is excessive information disclosure.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect `os.Environ()` being passed to JSON response functions, but the admin token check may cause tools to deprioritize the finding.
