# Security Companion Document: main.rs

## Vulnerability: Overly Permissive CORS Configuration

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L207-L211  

### Description
The Actix-web CORS configuration uses `allow_any_origin()`, `allow_any_method()`, `allow_any_header()`, and `supports_credentials()`. This combination allows any website to make authenticated cross-origin requests with any HTTP method and headers, effectively disabling the same-origin policy.

### Exploitation Scenario
An attacker hosts a malicious page that makes `fetch()` requests with `credentials: 'include'` to the API. The server allows any origin with credentials, so the browser sends the victim's cookies. The attacker reads product data, settings, or admin diagnostics from the victim's session.

### Remediation Guidance
Restrict CORS to specific trusted origins:
```rust
let cors = Cors::default()
    .allowed_origin("https://app.acmecorp.io")
    .allowed_methods(vec!["GET", "POST", "PUT"])
    .allowed_headers(vec!["Content-Type", "Authorization"])
    .supports_credentials();
```

### Complexity Rationale
This is rated Moderate because the CORS configuration uses Actix-web's builder pattern, which appears clean and intentional. A reviewer must understand that `allow_any_origin()` combined with `supports_credentials()` defeats the same-origin policy.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand Actix-web's CORS builder API and recognize that `allow_any_origin()` combined with `supports_credentials()` is a dangerous combination.

---

## Vulnerability: XML Parsing Without Entity Restrictions (Limited XXE Surface)

**CWE:** CWE-611  
**OWASP:** A05  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L79-L84  

### Description
The product import endpoint uses `roxmltree::Document::parse()` to process user-supplied XML. While `roxmltree` does not resolve external entities by default, the application performs no validation or sanitization of the XML input, and the lack of explicit DTD rejection means the parser accepts DTD declarations. In a scenario where the XML parsing library is swapped or updated to one that does resolve entities, the code would be immediately vulnerable to XXE.

### Exploitation Scenario
A developer replaces `roxmltree` with a more feature-rich XML library (e.g., one wrapping libxml2) without adding XXE protections. The existing code has no defensive measures, so the new library's default entity resolution immediately enables file reading and SSRF via crafted XML payloads. Even with `roxmltree`, accepting arbitrary DTD declarations in untrusted XML is a defense-in-depth failure.

### Remediation Guidance
Add explicit XML input validation and reject DTD declarations:
```rust
if xml_str.contains("<!DOCTYPE") || xml_str.contains("<!ENTITY") {
    return HttpResponse::BadRequest()
        .json(serde_json::json!({"error": "DTD declarations not allowed"}));
}
```

### Complexity Rationale
This is rated Nuanced because `roxmltree` is safe by default for XXE, but the code lacks any defensive measures. Recognizing this as a misconfiguration requires understanding defense-in-depth principles and the risk of library changes.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would see `roxmltree` (which is safe by default) and not flag the lack of explicit DTD rejection. The vulnerability is latent and depends on future code changes.

---

## Vulnerability: Unrestricted Settings Modification Without Authentication

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L155-L161  

### Description
The `PUT /api/settings` endpoint accepts arbitrary key-value pairs and merges them into the settings map without authentication or input validation. Any unauthenticated user can modify security-critical settings including `tls_verify`, `rate_limit`, `log_level`, and `allowed_origins`.

### Exploitation Scenario
An attacker sends `PUT /api/settings` with `{"tls_verify": false, "rate_limit": 0}` to disable TLS verification and remove rate limiting. With security controls weakened, the attacker proceeds to exfiltrate data or brute-force credentials without detection.

### Remediation Guidance
Add authentication and restrict modifiable settings:
```rust
async fn update_settings(req: HttpRequest, body: web::Json<HashMap<String, serde_json::Value>>, state: web::Data<AppState>) -> HttpResponse {
    let token = req.headers().get("X-Admin-Token")
        .and_then(|v| v.to_str().ok()).unwrap_or("");
    if token != ADMIN_TOKEN {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}));
    }
    let allowed = ["maintenance_mode", "max_upload_size"];
    let mut settings = state.settings.lock().unwrap();
    for (k, v) in body.into_inner() {
        if allowed.contains(&k.as_str()) { settings.insert(k, v); }
    }
    HttpResponse::Ok().json(serde_json::json!({"message": "Settings updated"}))
}
```

### Complexity Rationale
This is rated Nuanced because the endpoint appears to be a standard CRUD operation. Recognizing the security impact requires understanding which settings are security controls and that the endpoint lacks authentication.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine which settings are security-critical or that the endpoint lacks authentication. This is a business logic flaw.

---

## Vulnerability: Diagnostics Endpoint Exposes Database Credentials

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L163-L178  

### Description
The `/api/admin/diagnostics` endpoint returns the database host, username, and password as JSON fields, along with all application settings. While protected by a static admin token, the token is hardcoded in the source code as a constant.

### Exploitation Scenario
An attacker who discovers the hardcoded token `super-admin-token-2024` sends `GET /api/admin/diagnostics` and receives the database password `Pg_Pr0d#2024` and all settings. The attacker uses the database credentials for direct database access.

### Remediation Guidance
Remove sensitive data from diagnostic responses:
```rust
HttpResponse::Ok().json(serde_json::json!({
    "product_count": products.len(),
    "settings_count": settings.len(),
}))
```

### Complexity Rationale
This is rated Moderate because the endpoint is admin-protected, which may seem sufficient. A reviewer must recognize that exposing raw database credentials through any endpoint is excessive information disclosure.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect hardcoded credential constants flowing into HTTP response bodies, but the admin token check may cause tools to deprioritize the finding.

---

## Vulnerability: Environment Variables Exposed via Admin Endpoint

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L180-L192  

### Description
The `/api/admin/env` endpoint collects all environment variables via `std::env::vars()` and returns them in the JSON response. Environment variables commonly contain cloud credentials, API keys, database connection strings, and other secrets.

### Exploitation Scenario
An attacker who obtains the admin token sends `GET /api/admin/env` and receives all environment variables, which may include `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, or other sensitive values. The attacker uses these credentials to access cloud resources or databases.

### Remediation Guidance
Remove the environment variable endpoint entirely, or return only non-sensitive operational metrics:
```rust
async fn get_env(req: HttpRequest) -> HttpResponse {
    // Remove this endpoint or restrict to specific safe variables
    HttpResponse::NotFound().json(serde_json::json!({"error": "Not found"}))
}
```

### Complexity Rationale
This is rated Obvious because `std::env::vars()` being collected and returned in a JSON response is immediately visible and clearly exposes all environment variables.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match `std::env::vars()` flowing into HTTP response bodies through straightforward data flow analysis.
