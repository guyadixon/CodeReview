# Security Companion Document: main.rs

## Vulnerability: Hardcoded Database Connection String and SMTP Credentials

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L30-L32  

### Description
The application stores the full PostgreSQL connection string (including username and password), SMTP host, and SMTP password as `const` string literals. The connection string `postgresql://appuser:Pg_Pr0d#2024@db.internal.acmecorp.io:5432/designdb` embeds the password directly in the URI, and the SMTP password `SmtpR3lay#2024!` is a separate constant. These are compiled into the binary and extractable via string analysis.

### Exploitation Scenario
An attacker who obtains the compiled binary runs `strings` on it and extracts the PostgreSQL connection URI with embedded credentials. They connect to `db.internal.acmecorp.io:5432` as `appuser` and dump the entire database. The SMTP credentials allow sending emails from the corporate domain.

### Remediation Guidance
Load credentials from environment variables at runtime:
```rust
let db_connection = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
let smtp_host = std::env::var("SMTP_HOST").expect("SMTP_HOST must be set");
let smtp_password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext `const` string literals with descriptive names, immediately visible at the top of the file.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded connection strings containing password patterns and credential-named constants through simple pattern matching.

---

## Vulnerability: Database Connection String Leaked in Error Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L252-L256  

### Description
The report generation handler constructs an error message containing the full database connection string (with embedded password) and returns it in the JSON error response. The `DB_CONNECTION` constant, which contains the PostgreSQL URI with credentials, is included in both the simulated error message and the `connection_string` response field.

### Exploitation Scenario
An authenticated attacker sends `POST /api/reports/generate` with any report type. The error response includes `"connection_string": "postgresql://appuser:Pg_Pr0d#2024@db.internal.acmecorp.io:5432/designdb"`, directly exposing the database credentials and internal hostname.

### Remediation Guidance
Log errors server-side and return generic messages:
```rust
Err(e) => {
    eprintln!("Report generation failed: {}", e);
    HttpResponse::InternalServerError().json(serde_json::json!({"error": "Report generation failed"}))
}
```

### Complexity Rationale
This is rated Moderate because the error handling appears to be a debugging aid. A reviewer must recognize that including connection strings with embedded credentials in HTTP responses is a security concern.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the `DB_CONNECTION` constant into the Actix-web JSON response. Tools that track constant propagation into HTTP response bodies can flag this.

---

## Vulnerability: Debug Endpoint Exposes Full User Records Including Passwords

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L284-L296  

### Description
The `/api/debug/user/{id}` endpoint serializes the complete `User` struct (which derives `Serialize`) and returns it as JSON. Since the `User` struct includes the `password` field with a serde attribute, the plaintext password is included in the response. Any authenticated user can query any other user's full record.

### Exploitation Scenario
An authenticated low-privilege user sends `GET /api/debug/user/1` and receives the admin's complete record including `"password": "Adm1n_Pr0d!"`. The attacker uses this to escalate privileges by logging in as admin.

### Remediation Guidance
Create a separate response struct that excludes sensitive fields:
```rust
#[derive(Serialize)]
struct UserResponse {
    id: u32,
    username: String,
    email: String,
    role: String,
}
```

### Complexity Rationale
This is rated Moderate because Rust's `#[derive(Serialize)]` on the `User` struct makes it convenient to serialize all fields. A reviewer must notice that the struct includes a `password` field that will be serialized.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to understand serde serialization semantics and determine that a `password` field in a `Serialize`-derived struct constitutes information disclosure when returned in an HTTP response.

---

## Vulnerability: Password Reset Token and SMTP Server Returned in API Response

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L156-L160  

### Description
The password reset endpoint returns the generated reset token and the internal SMTP server hostname in the API response. The token should only be delivered via email. Returning it allows any caller to reset any user's password without email access, and the SMTP hostname reveals internal infrastructure.

### Exploitation Scenario
An attacker sends `POST /api/password-reset` with `{"email": "admin@acmecorp.io"}`. The response includes the reset token and `mail.internal.acmecorp.io`. The attacker immediately resets the admin password via the confirm endpoint.

### Remediation Guidance
Send the token via email only and return a generic message:
```rust
HttpResponse::Ok().json(serde_json::json!({"message": "If the email exists, a reset link has been sent"}))
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
**Affected Lines:** L272-L278  

### Description
The `/api/config` endpoint returns the full database connection string (with embedded password), SMTP host, and SMTP password in the JSON response. While restricted to admin users, transmitting credentials over the network exposes them to interception and logging.

### Exploitation Scenario
An attacker who compromises an admin session calls `GET /api/config` and obtains the database connection string with embedded password and SMTP credentials, providing persistent access to backend infrastructure.

### Remediation Guidance
Return only non-sensitive operational data:
```rust
HttpResponse::Ok().json(serde_json::json!({
    "session_count": session_count,
    "user_count": users.len(),
}))
```

### Complexity Rationale
This is rated Nuanced because the admin-only restriction provides a false sense of security. Credentials should never be transmitted through API responses regardless of access controls.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can trace credential constants into response bodies, but the admin access guard may reduce the severity assessment.
