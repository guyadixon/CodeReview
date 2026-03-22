# Security Companion Document: app.py

## Vulnerability: Overly Permissive CORS Configuration

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L35-L41  

### Description
The `after_request` handler reflects the request's `Origin` header directly into the `Access-Control-Allow-Origin` response header while simultaneously setting `Access-Control-Allow-Credentials` to `true`. This combination allows any website to make authenticated cross-origin requests to the API, effectively bypassing the same-origin policy. The wildcard `*` fallback and unrestricted methods/headers compound the issue.

### Exploitation Scenario
An attacker hosts a malicious page at `https://evil.example.com` that makes `fetch()` requests with `credentials: 'include'` to the API. Because the server reflects the attacker's origin and allows credentials, the browser sends the victim's session cookies. The attacker's JavaScript reads the response containing product data, settings, or admin diagnostics from the victim's authenticated session.

### Remediation Guidance
Validate the `Origin` header against an explicit allowlist:
```python
ALLOWED_ORIGINS = {"https://app.acmecorp.io", "https://admin.acmecorp.io"}

@app.after_request
def add_headers(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response
```

### Complexity Rationale
This is rated Moderate because the CORS headers are set in a centralized `after_request` handler, which is a common Flask pattern. A reviewer must understand that reflecting arbitrary origins with credentials enabled is dangerous, even though each header individually might appear benign.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize the combination of origin reflection plus `Allow-Credentials: true` as a vulnerability. Tools that only check for `Access-Control-Allow-Origin: *` may miss the reflected origin variant.

---

## Vulnerability: Debug Mode Enabled in Production Configuration

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L8-L10  

### Description
The Flask application has `DEBUG` set to `True` and `PROPAGATE_EXCEPTIONS` enabled. Debug mode activates the Werkzeug interactive debugger, which provides a Python REPL in the browser when an unhandled exception occurs. The `SECRET_KEY` is set to the trivially guessable value `"changeme"`, which allows session cookie forgery.

### Exploitation Scenario
An attacker triggers an unhandled exception (e.g., by sending malformed input) and gains access to the Werkzeug debugger console in the browser. From the console, the attacker executes arbitrary Python code on the server: `import os; os.system("cat /etc/passwd")`. Separately, the weak `SECRET_KEY` allows the attacker to forge Flask session cookies and impersonate any user.

### Remediation Guidance
Disable debug mode and use a strong, randomly generated secret key:
```python
app.config["DEBUG"] = False
app.config["PROPAGATE_EXCEPTIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
```

### Complexity Rationale
This is rated Obvious because `DEBUG = True` and `SECRET_KEY = "changeme"` are plaintext configuration values at the top of the file, immediately visible during any code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match `DEBUG = True` and weak secret key patterns through simple string matching on Flask configuration assignments.

---

## Vulnerability: XML External Entity (XXE) Processing in Product Import

**CWE:** CWE-611  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L80-L82  

### Description
The product import endpoint creates an `lxml` XML parser with `resolve_entities=True` and `no_network=False`. This configuration allows the parser to process external entity declarations in XML input, enabling an attacker to read arbitrary files from the server or make outbound network requests via the XML parser.

### Exploitation Scenario
An attacker sends a POST request to `/api/products/import` with a crafted XML payload containing an external entity definition:
```xml
<?xml version="1.0"?>
<!DOCTYPE products [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<products><product><name>&xxe;</name><sku>X</sku><price>0</price><stock>0</stock></product></products>
```
The server resolves `&xxe;` to the contents of `/etc/passwd` and returns it in the product name field of the JSON response.

### Remediation Guidance
Disable entity resolution in the lxml parser:
```python
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
```

### Complexity Rationale
This is rated Moderate because the parser configuration flags are explicit but require knowledge of what `resolve_entities` and `no_network` do in the context of XXE attacks. The vulnerability is in the parser construction, not in how the parsed data is used.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools have well-known rules for detecting `XMLParser(resolve_entities=True)` and similar XXE-enabling configurations in lxml.

---

## Vulnerability: Verbose Error Handling Exposes Stack Traces

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L160-L166  

### Description
The global exception handler returns the full Python traceback, exception class name, and exception message in the JSON error response. This information disclosure reveals internal file paths, library versions, and code structure to any client that triggers an unhandled exception.

### Exploitation Scenario
An attacker sends malformed requests to various endpoints to trigger exceptions. The error responses reveal the application's directory structure (`/app/venv/lib/python3.10/...`), installed package versions, and internal function names. The attacker uses this information to identify known CVEs in the installed packages and craft targeted exploits.

### Remediation Guidance
Log detailed errors server-side and return generic messages to clients:
```python
@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.exception("Unhandled exception")
    return jsonify({"error": "Internal server error"}), 500
```

### Complexity Rationale
This is rated Moderate because error handlers that include tracebacks are a common development pattern. A reviewer must recognize that returning `traceback.format_exc()` to API clients is an information disclosure risk, not just a debugging convenience.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace `traceback.format_exc()` into HTTP response bodies. Tools with framework-aware rules for Flask's `errorhandler` can detect this pattern.

---

## Vulnerability: Unrestricted Settings Modification

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L131-L137  

### Description
The `PUT /api/settings` endpoint accepts arbitrary key-value pairs and merges them directly into the application settings dictionary without any validation or authorization check. Any unauthenticated user can modify security-critical settings such as `tls_verify`, `log_level`, `rate_limit`, and `allowed_origins`, effectively reconfiguring the application's security posture at runtime.

### Exploitation Scenario
An attacker sends `PUT /api/settings` with `{"tls_verify": true, "rate_limit": 0, "log_level": "CRITICAL"}` to disable rate limiting and suppress logging. They then send `{"allowed_origins": "https://evil.example.com"}` to restrict CORS to their own domain (or keep it open). With logging suppressed and rate limiting disabled, the attacker proceeds to brute-force admin tokens or exfiltrate data without detection.

### Remediation Guidance
Add authentication, authorization, and input validation to the settings endpoint:
```python
MUTABLE_SETTINGS = {"maintenance_mode", "max_upload_size"}

@app.route("/api/settings", methods=["PUT"])
def update_settings():
    token = request.headers.get("X-Admin-Token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    for key, value in data.items():
        if key in MUTABLE_SETTINGS:
            SETTINGS[key] = value
    return jsonify({"message": "Settings updated", "settings": SETTINGS})
```

### Complexity Rationale
This is rated Nuanced because the endpoint appears to be a standard CRUD operation for application settings. Recognizing the security impact requires understanding that certain settings (TLS verification, rate limiting, logging level) are security controls, and that the lack of authentication on this endpoint allows any user to weaken the application's defenses.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine which settings are security-critical or that the endpoint lacks authentication. This is a business logic and authorization flaw that requires understanding the application's security model.

---

## Vulnerability: Diagnostics Endpoint Exposes Environment Variables and Database Credentials

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L140-L152  

### Description
The `/api/admin/diagnostics` endpoint returns the full database connection string (including password), the upload directory path, all application settings, the complete set of environment variables (which may contain API keys, tokens, and other secrets), and the Python module search path. While protected by a static admin token, the token itself is hardcoded in the source code.

### Exploitation Scenario
An attacker who discovers the hardcoded admin token `super-admin-token-2024` (from source code access, a leaked repository, or brute-forcing) sends `GET /api/admin/diagnostics` and receives the database connection string `postgresql://appuser:Pg_Pr0d#2024@db.internal.acmecorp.io:5432/configdb`, all environment variables (potentially including cloud provider credentials), and the full settings map. The attacker uses the database credentials to connect directly to the production database.

### Remediation Guidance
Remove sensitive data from diagnostic endpoints and use proper secret management:
```python
@app.route("/api/admin/diagnostics", methods=["GET"])
def diagnostics():
    # ... auth check ...
    return jsonify({
        "settings": {k: v for k, v in SETTINGS.items() if k not in ("tls_verify",)},
        "product_count": len(PRODUCTS),
        "debug_mode": app.config["DEBUG"],
    })
```

### Complexity Rationale
This is rated Moderate because the endpoint is admin-protected, which may give a false sense of security. A reviewer must recognize that exposing `dict(os.environ)` and raw database connection strings through any endpoint creates excessive information disclosure.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially detect `os.environ` being passed to `jsonify()`, but the admin token check may cause tools to deprioritize the finding. Tools need to understand that the protection is insufficient given the hardcoded token.
