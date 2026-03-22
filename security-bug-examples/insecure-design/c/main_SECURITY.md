# Security Companion Document: main.c

## Vulnerability: Hardcoded Database and SMTP Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L13-L17  

### Description
The application stores database host, username, password, SMTP host, and SMTP password as `static const char *` string literals. The database password `Pg_Pr0d#2024` and SMTP password `SmtpR3lay#2024!` are embedded directly in the source code and compiled into the binary, making them extractable via the `strings` command on the compiled executable.

### Exploitation Scenario
An attacker runs `strings design-api | grep -i pass` on the compiled binary and extracts `Pg_Pr0d#2024` and `SmtpR3lay#2024!`. They connect to `db.internal.acmecorp.io` as `appuser` to access the database, and use the SMTP credentials to send phishing emails from the corporate mail relay.

### Remediation Guidance
Read credentials from environment variables or a configuration file with restricted permissions:
```c
const char *db_pass = getenv("DB_PASS");
const char *smtp_pass = getenv("SMTP_PASS");
if (!db_pass || !smtp_pass) {
    fprintf(stderr, "Required credentials not set\n");
    exit(1);
}
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string literals assigned to clearly named static variables at the top of the file.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants assigned to variables with credential-related names through simple pattern matching.

---

## Vulnerability: Database Credentials Leaked in Error Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L342-L348  

### Description
The report generation handler constructs an error response that includes the database host, username, and password in the error details. When a report fails to generate, the response body contains the full database credentials formatted into the JSON string, exposing them to any authenticated user.

### Exploitation Scenario
An authenticated attacker sends `POST /api/reports/generate` with `{"type": "anything"}`. The error response includes `"details": "Could not connect to database at db.internal.acmecorp.io as user 'appuser' with password 'Pg_Pr0d#2024'"`, directly exposing all database credentials.

### Remediation Guidance
Return generic error messages and log details server-side:
```c
snprintf(resp, sizeof(resp), "{\"error\":\"Report generation failed\"}");
fprintf(stderr, "Report failed: could not connect to %s\n", DB_HOST);
return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
```

### Complexity Rationale
This is rated Moderate because the error message appears to be a debugging aid. A reviewer must recognize that formatting database credentials into HTTP response bodies is a security concern.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the credential variables (`DB_HOST`, `DB_USER`, `DB_PASS`) through `snprintf` into the HTTP response. Tools that track data flow from credential constants to output functions can flag this.

---

## Vulnerability: Debug Endpoint Exposes Full User Records Including Passwords

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L313-L330  

### Description
The `/api/debug/user/{id}` endpoint formats and returns the complete user struct including the plaintext password, role, active status, and failed attempt count. Any authenticated user can query any other user's full record without role-based authorization.

### Exploitation Scenario
An authenticated viewer-role user sends `GET /api/debug/user/1` and receives the admin's complete record including `"password":"Adm1n_Pr0d!"`. The attacker uses this password to log in as admin and access all privileged endpoints.

### Remediation Guidance
Exclude sensitive fields from the response:
```c
snprintf(resp, sizeof(resp),
         "{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\",\"role\":\"%s\"}",
         u->id, u->username, u->email, u->role);
```

### Complexity Rationale
This is rated Moderate because the endpoint name "debug" suggests intentional development tooling. A reviewer must recognize that including the password field in any API response is a critical design flaw.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to understand that the `password` field of the user struct is sensitive and that formatting it into an HTTP response constitutes information disclosure.

---

## Vulnerability: Password Reset Token and SMTP Server Returned in API Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L245-L249  

### Description
The password reset endpoint returns the generated reset token and the internal SMTP server hostname in the API response. The token should only be delivered via email. Returning it allows any caller to reset any user's password without email access, and the SMTP hostname reveals internal infrastructure.

### Exploitation Scenario
An attacker sends `POST /api/password-reset` with `{"email": "admin@acmecorp.io"}`. The response includes the reset token and `mail.internal.acmecorp.io`. The attacker immediately resets the admin password via the confirm endpoint.

### Remediation Guidance
Send the token via email only:
```c
snprintf(resp, sizeof(resp), "{\"message\":\"If the email exists, a reset link has been sent\"}");
```

### Complexity Rationale
This is rated Nuanced because the token return may appear intentional for development. Recognizing this as a design flaw requires understanding that email delivery is the authentication factor in password reset flows.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools lack semantic understanding of password reset security models and cannot determine that returning tokens in responses defeats the intended design.

---

## Vulnerability: Config Endpoint Exposes All Infrastructure Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L303-L310  

### Description
The `/api/config` endpoint returns the database host, username, password, SMTP host, and SMTP password in the JSON response. While restricted to admin users, transmitting credentials over the network exposes them to interception, proxy logging, and caching.

### Exploitation Scenario
An attacker who compromises an admin session calls `GET /api/config` and obtains all infrastructure credentials including `Pg_Pr0d#2024` and `SmtpR3lay#2024!`, providing persistent access to backend systems.

### Remediation Guidance
Return only non-sensitive operational data:
```c
snprintf(resp, sizeof(resp),
         "{\"session_count\":%d,\"user_count\":%d}",
         session_count, user_count);
```

### Complexity Rationale
This is rated Nuanced because the admin-only restriction provides a false sense of security. Credentials should never be transmitted through API responses regardless of access controls.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can trace credential constants through `snprintf` into the response, but the admin access guard may reduce the severity assessment.
