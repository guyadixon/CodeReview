# Security Companion Document: main.go

## Vulnerability: Hardcoded Database DSN and SMTP Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L37-L39  

### Description
The application stores the full PostgreSQL connection DSN (including host, port, username, and password) and SMTP credentials as package-level variables. The DSN `host=db.internal.acmecorp.io port=5432 user=appuser password=Pg_Pr0d#2024 dbname=designdb sslmode=disable` and SMTP password `SmtpR3lay#2024!` are embedded directly in the source code, granting anyone with code access full database and mail relay credentials.

### Exploitation Scenario
An attacker who obtains the source code extracts the PostgreSQL DSN and connects directly to `db.internal.acmecorp.io:5432` as `appuser` with password `Pg_Pr0d#2024`. They dump the entire `designdb` database, modify records, or pivot to other services accessible from the database server. The SMTP credentials allow sending emails from the corporate domain.

### Remediation Guidance
Load credentials from environment variables:
```go
var (
    dbDSN        = os.Getenv("DATABASE_DSN")
    smtpHost     = os.Getenv("SMTP_HOST")
    smtpPassword = os.Getenv("SMTP_PASSWORD")
)
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string literals assigned to clearly named package-level variables, immediately visible at the top of the file.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded connection strings and credential patterns through regex matching on variable names and string content containing passwords.

---

## Vulnerability: Database DSN and Stack Trace Leaked in Error Responses

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L296-L323  

### Description
The report generation handler returns detailed error information when database operations fail, including the raw error message, the full Go debug stack trace (`debug.Stack()`), and the complete database DSN containing credentials. This occurs in two error paths: the initial connection failure and the query execution failure.

### Exploitation Scenario
An authenticated attacker sends `POST /api/reports/generate` with `{"type": "users"}`. When the database connection fails, the response includes the full DSN `host=db.internal.acmecorp.io port=5432 user=appuser password=Pg_Pr0d#2024 dbname=designdb sslmode=disable` along with the Go stack trace revealing internal package paths and function names.

### Remediation Guidance
Log errors server-side and return generic messages:
```go
import "log"

if err != nil {
    log.Printf("Report generation failed: %v", err)
    c.JSON(http.StatusInternalServerError, gin.H{"error": "Report generation failed"})
    return
}
```

### Complexity Rationale
This is rated Moderate because returning error details is a common development pattern. A reviewer must recognize that including the DSN (with embedded password) and stack traces in HTTP responses is a security concern.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the `debug.Stack()` call and DSN variable into the Gin JSON response context. Tools that recognize `debug.Stack()` in HTTP handler functions can flag this.

---

## Vulnerability: Debug Endpoint Exposes Full User Records Including Passwords

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L356-L379  

### Description
The `/api/debug/user/:id` endpoint serializes and returns the complete `User` struct including the `Password` field to any authenticated user. Since the `User` struct has `json:"password"` tags, the password is included in the JSON response. No role-based authorization is enforced beyond basic session validation.

### Exploitation Scenario
An authenticated viewer-role user sends `GET /api/debug/user/1` and receives the admin's complete record including `"password": "Adm1n_Pr0d!"`. The attacker uses this password to log in as admin and access all privileged endpoints.

### Remediation Guidance
Exclude sensitive fields from the response or restrict the endpoint to admin users:
```go
c.JSON(http.StatusOK, gin.H{
    "id": user.ID, "username": user.Username,
    "email": user.Email, "role": user.Role,
})
```

### Complexity Rationale
This is rated Moderate because the Go struct serialization with JSON tags makes it easy to accidentally expose all fields. A reviewer must notice that the `Password` field has a JSON tag and will be included in `c.JSON(http.StatusOK, user)`.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to understand Go struct JSON serialization semantics and determine that a field named "password" in a serialized struct constitutes information disclosure.

---

## Vulnerability: Password Reset Token and SMTP Server Returned in API Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L186-L191  

### Description
The password reset endpoint returns the generated reset token and the internal SMTP server hostname in the API response. The token should only be sent via email. Returning it allows any caller to reset any user's password without email access. The SMTP hostname leaks internal infrastructure details.

### Exploitation Scenario
An attacker sends `POST /api/password-reset` with `{"email": "admin@acmecorp.io"}`. The response includes the reset token and `mail.internal.acmecorp.io`. The attacker immediately resets the admin password and gains full access.

### Remediation Guidance
Send the token via email only:
```go
c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a reset link has been sent"})
```

### Complexity Rationale
This is rated Nuanced because the token return may appear intentional for development. Recognizing this as a design flaw requires understanding that email delivery is the authentication factor in password reset flows.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools lack semantic understanding of password reset flow security models and cannot determine that returning tokens in responses defeats the intended design.

---

## Vulnerability: Config Endpoint Exposes All Infrastructure Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L347-L353  

### Description
The `/api/config` endpoint returns the full database DSN (including password), SMTP host, and SMTP password in the JSON response. While restricted to admin users, transmitting credentials over the network exposes them to interception, logging, and caching.

### Exploitation Scenario
An attacker who compromises an admin session calls `GET /api/config` and obtains the database DSN with embedded password and SMTP credentials. These credentials provide persistent access to backend infrastructure beyond the session lifetime.

### Remediation Guidance
Return only non-sensitive operational metrics:
```go
c.JSON(http.StatusOK, gin.H{
    "session_count": len(sessions),
    "user_count":    len(users),
})
```

### Complexity Rationale
This is rated Nuanced because the admin-only restriction provides a false sense of security. A reviewer must understand that credentials should never be transmitted through API responses regardless of access controls.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can trace credential variables into Gin response calls, but the admin guard may reduce the severity assessment.
