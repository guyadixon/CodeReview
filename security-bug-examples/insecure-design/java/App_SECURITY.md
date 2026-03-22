# Security Companion Document: App.java

## Vulnerability: Hardcoded Database and SMTP Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L22-L26  

### Description
The application stores database connection URL, database username, database password, SMTP host, and SMTP credential as `static final` string constants. These credentials are compiled into the class file and visible to anyone with access to the source code or the decompiled bytecode. The database password `admin123` and SMTP credential `SmtpRelay#Prod2024!` grant direct access to backend infrastructure.

### Exploitation Scenario
An attacker who obtains the compiled JAR or source code extracts the database URL `jdbc:h2:mem:designdb` with credentials `sa/admin123` and the SMTP credential. While the H2 in-memory database is local, the SMTP credential allows the attacker to connect to `smtp.internal.acmecorp.io` and send emails from the corporate domain for phishing campaigns.

### Remediation Guidance
Load credentials from environment variables or a configuration service:
```java
private static final String DB_URL = System.getenv("DB_URL");
private static final String DB_USER = System.getenv("DB_USER");
private static final String DB_PASS = System.getenv("DB_PASS");
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext `static final` constants with descriptive names like `DB_PASS` and `SMTP_CREDENTIAL`, immediately visible at the top of the class.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded strings assigned to variables with credential-related names through straightforward pattern matching.

---

## Vulnerability: Full Stack Trace and Database URL Leaked in Error Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L273-L282  

### Description
The report generation endpoint catches SQL exceptions and returns the full Java stack trace (via `PrintWriter`/`StringWriter`), the exception message, and the database URL in the error response. This exposes internal class names, method signatures, library versions, and database connection details to any authenticated user who triggers a database error.

### Exploitation Scenario
An authenticated attacker sends `POST /api/reports/generate` with `{"type": "nonexistent"}`. The SQL exception response includes the full stack trace revealing Spring Boot internals, H2 driver version, and the database URL `jdbc:h2:mem:designdb`. The attacker uses this to identify specific library versions with known vulnerabilities and craft targeted exploits.

### Remediation Guidance
Log exceptions server-side and return generic error messages:
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

private static final Logger logger = LoggerFactory.getLogger(App.class);

} catch (Exception e) {
    logger.error("Report generation failed", e);
    return ResponseEntity.status(500).body(Map.of("error", "Report generation failed"));
}
```

### Complexity Rationale
This is rated Moderate because the error handling pattern of catching exceptions and returning details is common in development. A reviewer must recognize that serializing stack traces into HTTP responses is a security concern in production.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect `printStackTrace` or `StringWriter` patterns flowing into HTTP responses, but need to understand the web response context to flag it as information disclosure.

---

## Vulnerability: Debug Endpoint Exposes Complete User Records Including Passwords

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L306-L319  

### Description
The `/api/debug/user/{userId}` endpoint returns the complete user map including the plaintext password, failed attempt count, and all other fields. Any authenticated user can query any other user's full record without role-based authorization checks beyond basic session validation.

### Exploitation Scenario
A low-privilege authenticated user sends `GET /api/debug/user/1` and receives the admin's complete record including `"password": "Adm1n_Pr0d!"`. The attacker logs in as admin and accesses the configuration endpoint to extract all infrastructure credentials.

### Remediation Guidance
Remove debug endpoints from production, or restrict to admin access and filter sensitive fields:
```java
@GetMapping("/api/debug/user/{userId}")
public ResponseEntity<?> debugUser(@RequestHeader("Authorization") String auth,
                                    @PathVariable int userId) {
    // ... verify admin role ...
    Map<String, Object> user = users.get(userId);
    return ResponseEntity.ok(Map.of(
        "id", user.get("id"), "username", user.get("username"),
        "email", user.get("email"), "role", user.get("role")));
}
```

### Complexity Rationale
This is rated Moderate because the endpoint is named "debug" which suggests intentional development tooling. A reviewer must recognize that returning password fields through any endpoint is a critical design flaw.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine which fields in a generic `Map<String, Object>` are sensitive. The vulnerability depends on understanding the data model semantics.

---

## Vulnerability: Password Reset Token and SMTP Server Leaked in Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L162-L166  

### Description
The password reset endpoint returns the generated reset token and the internal SMTP server hostname directly in the API response. The token should only be delivered via email to the account owner. Returning it in the response allows any caller to reset any user's password without email access, and the SMTP hostname reveals internal infrastructure.

### Exploitation Scenario
An attacker sends `POST /api/password-reset` with `{"email": "admin@acmecorp.io"}`. The response includes the reset token and `smtp.internal.acmecorp.io`. The attacker uses the token to reset the admin password immediately, and notes the SMTP server for future reconnaissance.

### Remediation Guidance
Send the token via email only and return a generic confirmation:
```java
return ResponseEntity.ok(Map.of("message", "If the email exists, a reset link has been sent"));
```

### Complexity Rationale
This is rated Nuanced because returning the token may appear intentional for development convenience. Recognizing this as a design flaw requires understanding that the email delivery channel is the security mechanism in password reset flows.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need semantic understanding of password reset flows to recognize that returning tokens in responses defeats the security model.

---

## Vulnerability: Admin Config Endpoint Exposes All Infrastructure Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L297-L303  

### Description
The `/api/config` endpoint returns the database URL, SMTP host, and SMTP credential in the JSON response. While restricted to admin users, transmitting credentials over HTTP means they appear in network logs, proxy caches, and browser history. Credentials should never be exposed through API responses.

### Exploitation Scenario
An attacker who compromises an admin session (via session hijacking or credential theft) calls `GET /api/config` and obtains all infrastructure credentials. These credentials persist beyond the session lifetime, giving the attacker long-term access to the database and SMTP servers.

### Remediation Guidance
Return only non-sensitive operational data:
```java
return ResponseEntity.ok(Map.of(
    "session_count", sessions.size(),
    "user_count", users.size(),
    "database_configured", true,
    "smtp_configured", true));
```

### Complexity Rationale
This is rated Nuanced because the admin-only access control provides a false sense of security. A reviewer must understand that even privileged endpoints should not expose raw credentials, as this violates defense-in-depth principles.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially trace credential constants flowing into response bodies, but the admin access guard may cause tools to deprioritize the finding.
