# Security Companion Document: app.js

## Vulnerability: Hardcoded Database and SMTP Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L6-L10  

### Description
The application stores database host, username, password, SMTP host, and SMTP password as module-level `const` variables. The database password `Pg_Pr0d#2024` and SMTP password `SmtpR3lay#2024!` are plaintext strings visible to anyone with source code access. User passwords in the `users` object are also stored in plaintext.

### Exploitation Scenario
An attacker who obtains the source code (via repository access, leaked deployment, or `.js` file served by a misconfigured server) extracts the database credentials and connects to `db.internal.acmecorp.io` as `appuser`. The SMTP credentials allow sending emails from the corporate domain for phishing campaigns.

### Remediation Guidance
Load credentials from environment variables:
```javascript
const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PASS = process.env.SMTP_PASS;
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string constants with descriptive names at the top of the file, immediately visible during any code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants assigned to variables with credential-related names through simple pattern matching.

---

## Vulnerability: Stack Trace and Database Credentials Leaked in Error Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L203-L219  

### Description
The report generation endpoint catches database errors and returns the JavaScript error stack trace (`err.stack`), the error message, and the full database credentials (host, user, password) in the JSON error response. This occurs in both the query callback error path and the outer try-catch block, exposing internal implementation details and credentials to any authenticated user.

### Exploitation Scenario
An authenticated attacker sends `POST /api/reports/generate` with `{"type": "nonexistent"}`. The error response includes the full Node.js stack trace revealing file paths and module versions, plus `"database": {"host": "db.internal.acmecorp.io", "user": "appuser", "password": "Pg_Pr0d#2024"}`, directly exposing all database credentials.

### Remediation Guidance
Log errors server-side and return generic messages:
```javascript
} catch (err) {
  console.error("Report generation failed:", err);
  return res.status(500).json({ error: "Report generation failed" });
}
```

### Complexity Rationale
This is rated Moderate because the error handling pattern of catching exceptions and returning details is common in Node.js development. A reviewer must recognize that including stack traces and credential objects in HTTP responses is a security concern.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace `err.stack` and credential variables into Express response calls. Tools that recognize error object properties flowing into `res.json()` can flag this.

---

## Vulnerability: Debug Endpoint Exposes Full User Records Including Passwords

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L244-L257  

### Description
The `/api/debug/user/:id` endpoint returns the complete user object including the plaintext password, failed attempt count, and all other fields via `res.json(user)`. Any authenticated user can query any other user's full record without role-based authorization checks.

### Exploitation Scenario
An authenticated viewer-role user sends `GET /api/debug/user/1` and receives the admin's complete record including `"password": "Adm1n_Pr0d!"`. The attacker uses this password to log in as admin and access all privileged endpoints including the config endpoint.

### Remediation Guidance
Exclude sensitive fields from the response:
```javascript
const { password, failedAttempts, ...safeUser } = user;
return res.json(safeUser);
```

### Complexity Rationale
This is rated Moderate because `res.json(user)` is a common Express pattern that serializes all object properties. A reviewer must recognize that the user object contains a `password` field that will be included in the response.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to understand that the `user` object contains sensitive properties and that passing it directly to `res.json()` constitutes information disclosure.

---

## Vulnerability: Password Reset Token and SMTP Server Returned in API Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L111-L115  

### Description
The password reset endpoint returns the generated reset token and the internal SMTP server hostname in the API response. The token should only be delivered via email. Returning it allows any caller to reset any user's password without email access, and the SMTP hostname reveals internal infrastructure.

### Exploitation Scenario
An attacker sends `POST /api/password-reset` with `{"email": "admin@acmecorp.io"}`. The response includes the reset token and `mail.internal.acmecorp.io`. The attacker immediately resets the admin password via the confirm endpoint.

### Remediation Guidance
Send the token via email only:
```javascript
return res.json({ message: "If the email exists, a reset link has been sent" });
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
**Affected Lines:** L233-L241  

### Description
The `/api/config` endpoint returns the database host, username, password, SMTP host, and SMTP password in the JSON response. While restricted to admin users, transmitting credentials over the network exposes them to interception, proxy logging, and browser caching.

### Exploitation Scenario
An attacker who compromises an admin session (via XSS, session fixation, or token theft) calls `GET /api/config` and obtains all infrastructure credentials. These credentials provide persistent access to backend systems beyond the session lifetime.

### Remediation Guidance
Return only non-sensitive operational data:
```javascript
return res.json({
  sessionCount: Object.keys(sessions).length,
  userCount: Object.keys(users).length,
  smtpConfigured: !!SMTP_HOST,
  databaseConfigured: !!DB_HOST,
});
```

### Complexity Rationale
This is rated Nuanced because the admin-only restriction provides a false sense of security. Credentials should never be transmitted through API responses regardless of access controls.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can trace credential constants into Express response calls, but the admin role check may reduce the severity assessment.
