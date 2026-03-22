# Security Companion Document: main.cpp

## Vulnerability: Hardcoded Database and SMTP Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L29-L33  

### Description
The application stores database host, username, password, SMTP host, and SMTP password as `static const std::string` variables. The database password `Pg_Pr0d#2024` and SMTP password `SmtpR3lay#2024!` are embedded in the source code and compiled into the binary, extractable via the `strings` command.

### Exploitation Scenario
An attacker runs `strings design_api | grep -i pass` on the compiled binary and extracts `Pg_Pr0d#2024` and `SmtpR3lay#2024!`. They connect to `db.internal.acmecorp.io` as `appuser` to access the database and use the SMTP credentials to send phishing emails from the corporate mail relay.

### Remediation Guidance
Read credentials from environment variables:
```cpp
static const std::string DB_PASS = []() {
    const char* val = std::getenv("DB_PASS");
    return val ? std::string(val) : "";
}();
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string constants with descriptive names like `DB_PASS` and `SMTP_PASS`, immediately visible at the top of the file.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants assigned to variables with credential-related names through simple pattern matching.

---

## Vulnerability: Database Credentials Leaked in Error Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L274-L280  

### Description
The report generation handler constructs a JSON error response that includes the database host, username, and password in the `details` field. When a report request is processed, the error response always contains the full database credentials formatted into the response string.

### Exploitation Scenario
An authenticated attacker sends `POST /api/reports/generate` with `{"type": "anything"}`. The error response includes `"details": "Could not connect to database at db.internal.acmecorp.io as user 'appuser' with password 'Pg_Pr0d#2024'"`, directly exposing all database credentials.

### Remediation Guidance
Return generic error messages:
```cpp
json resp = {{"error", "Report generation failed"}};
res.status = 500;
res.set_content(resp.dump(), "application/json");
```

### Complexity Rationale
This is rated Moderate because the error message construction appears to be a debugging aid. A reviewer must recognize that string-concatenating credential variables into HTTP response bodies is a security concern.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the credential variables (`DB_HOST`, `DB_USER`, `DB_PASS`) through string concatenation into the HTTP response. Tools that track data flow from credential constants to output functions can flag this.

---

## Vulnerability: Debug Endpoint Exposes Full User Records Including Passwords

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L307-L330  

### Description
The `/api/debug/user/{id}` endpoint constructs a JSON response containing all user struct fields including the plaintext password. Any authenticated user can query any other user's complete record without role-based authorization checks.

### Exploitation Scenario
An authenticated viewer-role user sends `GET /api/debug/user/1` and receives the admin's complete record including `"password": "Adm1n_Pr0d!"`. The attacker uses this password to log in as admin and access all privileged endpoints.

### Remediation Guidance
Exclude sensitive fields from the response:
```cpp
json resp = {
    {"id", it->second.id}, {"username", it->second.username},
    {"email", it->second.email}, {"role", it->second.role}
};
```

### Complexity Rationale
This is rated Moderate because the endpoint explicitly constructs the JSON with the password field. A reviewer must recognize that including password fields in any API response is a critical design flaw, even in "debug" endpoints.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to understand that the `password` member of the user struct is sensitive and that including it in a JSON response constitutes information disclosure.

---

## Vulnerability: Password Reset Token and SMTP Server Returned in API Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L171-L176  

### Description
The password reset endpoint returns the generated reset token and the internal SMTP server hostname in the API response. The token should only be delivered via email. Returning it allows any caller to reset any user's password without email access, and the SMTP hostname reveals internal infrastructure.

### Exploitation Scenario
An attacker sends `POST /api/password-reset` with `{"email": "admin@acmecorp.io"}`. The response includes the reset token and `mail.internal.acmecorp.io`. The attacker immediately resets the admin password via the confirm endpoint.

### Remediation Guidance
Send the token via email only:
```cpp
json resp = {{"message", "If the email exists, a reset link has been sent"}};
res.set_content(resp.dump(), "application/json");
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
**Affected Lines:** L299-L304  

### Description
The `/api/config` endpoint returns the database host, username, password, SMTP host, and SMTP password in the JSON response. While restricted to admin users, transmitting credentials over the network exposes them to interception, proxy logging, and caching.

### Exploitation Scenario
An attacker who compromises an admin session calls `GET /api/config` and obtains all infrastructure credentials including `Pg_Pr0d#2024` and `SmtpR3lay#2024!`, providing persistent access to backend systems.

### Remediation Guidance
Return only non-sensitive operational data:
```cpp
json resp = {
    {"session_count", sessions.size()}, {"user_count", users.size()}
};
```

### Complexity Rationale
This is rated Nuanced because the admin-only restriction provides a false sense of security. Credentials should never be transmitted through API responses regardless of access controls.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can trace credential constants into JSON response construction, but the admin access guard may reduce the severity assessment.
