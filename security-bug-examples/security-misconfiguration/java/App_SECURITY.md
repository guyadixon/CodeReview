# Security Companion Document: App.java

## Vulnerability: Overly Permissive CORS Configuration

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L72-L79  

### Description
The Spring `WebMvcConfigurer` bean configures CORS with `allowedOriginPatterns("*")`, `allowedMethods("*")`, `allowedHeaders("*")`, and `allowCredentials(true)`. This allows any origin to make authenticated cross-origin requests with any HTTP method and any headers, effectively disabling the same-origin policy for the entire application.

### Exploitation Scenario
An attacker hosts a malicious page that makes `fetch()` requests with `credentials: 'include'` to the API. The server allows the attacker's origin with credentials, so the browser sends the victim's session cookies. The attacker reads product data, settings, or admin diagnostics from the victim's authenticated session.

### Remediation Guidance
Restrict CORS to specific trusted origins:
```java
registry.addMapping("/api/**")
    .allowedOrigins("https://app.acmecorp.io")
    .allowedMethods("GET", "POST", "PUT")
    .allowedHeaders("Content-Type", "Authorization")
    .allowCredentials(true);
```

### Complexity Rationale
This is rated Moderate because the CORS configuration uses Spring's fluent API, which appears clean and intentional. A reviewer must understand that wildcard patterns with credentials enabled defeat the same-origin policy.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand Spring's CORS configuration API and recognize that `allowedOriginPatterns("*")` combined with `allowCredentials(true)` is a dangerous combination.

---

## Vulnerability: XML External Entity (XXE) Processing in Product Import

**CWE:** CWE-611  
**OWASP:** A05  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L113-L115  

### Description
The product import endpoint creates a `DocumentBuilderFactory` with `setExpandEntityReferences(true)` and does not disable external entity processing or DTD loading. The default Java XML parser configuration allows external entities, enabling XXE attacks that can read local files or make server-side requests.

### Exploitation Scenario
An attacker sends a POST to `/api/products/import` with:
```xml
<?xml version="1.0"?>
<!DOCTYPE products [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<products><product><name>&xxe;</name><sku>X</sku><price>0</price><stock>0</stock></product></products>
```
The server resolves the entity and returns the contents of `/etc/passwd` in the product name field.

### Remediation Guidance
Disable external entities and DTD processing:
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setExpandEntityReferences(false);
```

### Complexity Rationale
This is rated Obvious because `setExpandEntityReferences(true)` is an explicit call that directly enables entity expansion, and the absence of any XXE protection features is immediately apparent.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools have well-established rules for detecting Java `DocumentBuilderFactory` instances that lack XXE protection features.

---

## Vulnerability: Verbose Error Handling Exposes Stack Traces

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L195-L202  

### Description
The `@ExceptionHandler` method catches all exceptions and returns the exception class name, message, and full stack trace (via `PrintWriter`/`StringWriter`) in the JSON response. This reveals internal class paths, library versions, and code structure to any client that triggers an error.

### Exploitation Scenario
An attacker sends malformed XML or invalid JSON to trigger exceptions. The error responses reveal the application's package structure, Spring Boot version, and internal class names. The attacker uses this information to identify known CVEs and craft targeted exploits.

### Remediation Guidance
Log errors server-side and return generic messages:
```java
@ExceptionHandler(Exception.class)
public ResponseEntity<?> handleException(Exception e) {
    logger.error("Unhandled exception", e);
    return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
}
```

### Complexity Rationale
This is rated Moderate because exception handlers that include stack traces are common during development. A reviewer must recognize that returning stack traces to API clients is an information disclosure risk.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace `PrintWriter`/`StringWriter` stack trace output into HTTP response bodies within Spring exception handlers.

---

## Vulnerability: Unrestricted Settings Modification Without Authentication

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L186-L190  

### Description
The `PUT /api/settings` endpoint uses `settings.putAll(body)` to merge arbitrary key-value pairs into the application settings map without any authentication or input validation. Any unauthenticated user can modify security-critical settings such as `tls_verify`, `rate_limit`, `log_level`, and `allowed_origins`.

### Exploitation Scenario
An attacker sends `PUT /api/settings` with `{"tls_verify": true, "rate_limit": 0, "log_level": "ERROR"}` to disable rate limiting and suppress logging. With security controls weakened, the attacker brute-forces admin tokens or exfiltrates data without detection.

### Remediation Guidance
Add authentication and restrict modifiable settings:
```java
@PutMapping("/api/settings")
public ResponseEntity<?> updateSettings(
        @RequestHeader(value = "X-Admin-Token", defaultValue = "") String token,
        @RequestBody Map<String, Object> body) {
    if (!ADMIN_TOKEN.equals(token)) {
        return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
    }
    Set<String> allowed = Set.of("maintenance_mode", "max_upload_size");
    body.keySet().retainAll(allowed);
    settings.putAll(body);
    return ResponseEntity.ok(Map.of("message", "Settings updated", "settings", settings));
}
```

### Complexity Rationale
This is rated Nuanced because the endpoint appears to be a standard CRUD operation. Recognizing the security impact requires understanding which settings are security controls and that the endpoint lacks authentication.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine which settings are security-critical or that the endpoint lacks authentication. This is a business logic and authorization flaw.

---

## Vulnerability: Diagnostics Endpoint Exposes Database Credentials and System Properties

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L192-L206  

### Description
The `/api/admin/diagnostics` endpoint returns the database URL (including embedded password), database username and password as separate fields, Java version, OS name, working directory, and classpath. While protected by a static admin token, the token is hardcoded in the source code.

### Exploitation Scenario
An attacker who discovers the hardcoded token `super-admin-token-2024` sends `GET /api/admin/diagnostics` and receives the JDBC URL `jdbc:postgresql://db.internal.acmecorp.io:5432/configdb` with password `Pg_Pr0d#2024`, the classpath revealing all installed libraries, and the OS details. The attacker connects directly to the production database.

### Remediation Guidance
Remove sensitive data from diagnostic endpoints:
```java
info.put("product_count", products.size());
info.put("java_version", System.getProperty("java.version"));
info.put("settings_count", settings.size());
```

### Complexity Rationale
This is rated Moderate because the endpoint is admin-protected, which may seem sufficient. A reviewer must recognize that exposing raw database credentials and system properties through any endpoint is excessive information disclosure.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect hardcoded credential constants flowing into response bodies, but the admin token check may cause tools to deprioritize the finding.
