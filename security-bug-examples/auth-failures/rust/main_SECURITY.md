# Security Companion Document: main.rs

## Vulnerability: Hardcoded Admin Bootstrap Key and Inter-Service Token

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L7-L8  

### Description
The application defines two hardcoded credentials as module-level constants: `ADMIN_BOOTSTRAP_KEY` and `INTER_SERVICE_TOKEN`. The bootstrap key is used as a password for a "superadmin" account in the login endpoint, and the inter-service token is accepted as a valid token in the verification endpoint. These values are embedded in the compiled binary.

### Exploitation Scenario
An attacker who obtains the source code or reverse-engineers the binary extracts `abk_prod_2024_f8e7d6c5`. They send `POST /api/login` with `{"username": "bootstrap", "password": "abk_prod_2024_f8e7d6c5"}` and receive a session token with the "superadmin" role, gaining the highest level of access.

### Remediation Guidance
Load credentials from environment variables at runtime:
```rust
use std::env;

let admin_key = env::var("ADMIN_BOOTSTRAP_KEY").expect("ADMIN_BOOTSTRAP_KEY must be set");
let service_token = env::var("INTER_SERVICE_TOKEN").expect("INTER_SERVICE_TOKEN must be set");
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string constants at the top of the file, immediately visible to anyone reading the source code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants used in authentication comparisons through pattern matching on credential-like variable names.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L36-L38  

### Description
The `compute_md5` function uses the `md5` crate to hash user passwords. MD5 is a fast, unsalted hash function that is cryptographically broken for password storage. All user passwords in the `main` function are hashed with this weak function.

### Exploitation Scenario
An attacker who gains access to the user data obtains MD5 hashes. Using rainbow tables or GPU-accelerated tools, the attacker reverses the hashes in seconds, recovering plaintext passwords for all accounts.

### Remediation Guidance
Use bcrypt or argon2 for password hashing:
```rust
use bcrypt::{hash, verify, DEFAULT_COST};

fn hash_password(password: &str) -> String {
    hash(password, DEFAULT_COST).unwrap()
}
```

### Complexity Rationale
This is rated Moderate because the code uses the `md5` crate correctly from a functional standpoint. A reviewer must know that MD5 is specifically unsuitable for password hashing despite being a valid hash algorithm.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `md5::compute` usage through API pattern matching, especially in authentication-related code paths.

---

## Vulnerability: No Rate Limiting on Login Endpoint

**CWE:** CWE-307  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L58-L88  

### Description
The login handler processes unlimited authentication attempts without any rate limiting, account lockout, or delay mechanism. An attacker can perform unrestricted brute force or credential stuffing attacks against any user account.

### Exploitation Scenario
An attacker scripts thousands of `POST /api/login` requests per second targeting the "admin" account with passwords from a common password list. With no throttling or lockout, the attacker eventually discovers the correct password and gains admin access.

### Remediation Guidance
Add rate limiting middleware using actix-web-governor or similar:
```rust
use actix_governor::{Governor, GovernorConfigBuilder};

let governor_conf = GovernorConfigBuilder::default()
    .per_second(1)
    .burst_size(5)
    .finish()
    .unwrap();
```

### Complexity Rationale
This is rated Nuanced because the login handler itself is correctly implemented. The vulnerability is the absence of a defensive mechanism rather than a flaw in existing code.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools analyze existing code and generally cannot detect the absence of rate limiting middleware on authentication endpoints.

---

## Vulnerability: Hardcoded Inter-Service Token Bypasses Authentication

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L98-L102  

### Description
The token verification endpoint accepts the hardcoded `INTER_SERVICE_TOKEN` value as a valid authentication token, returning a successful verification with `user_id: 0` and `role: service`. This creates a permanent backdoor that bypasses the normal session-based authentication flow.

### Exploitation Scenario
An attacker who discovers the value `ist-mesh-auth-prod-2024` sends `POST /api/auth/verify` with `{"token": "ist-mesh-auth-prod-2024"}`. The response confirms the token is valid with service-level privileges. Any downstream service relying on this verification endpoint will trust the attacker as an internal service.

### Remediation Guidance
Remove the hardcoded token check and use proper service-to-service authentication with rotating credentials:
```rust
async fn verify_token(body: web::Json<VerifyRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if let Some(sess) = sessions.get(&body.token) {
        return HttpResponse::Ok().json(serde_json::json!({"valid": true, "userId": sess.user_id}));
    }
    HttpResponse::Unauthorized().json(serde_json::json!({"valid": false}))
}
```

### Complexity Rationale
This is rated Moderate because the hardcoded check is embedded within a function that also performs legitimate session validation. A reviewer must trace the control flow to notice the special-case bypass.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that comparing a request parameter against a constant in an authentication context constitutes a bypass.

---

## Vulnerability: Password Reset Token Exposed in API Response

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L131-L134  

### Description
The forgot-password endpoint returns the password reset token directly in the API response alongside the "Reset email sent" message. In production, the reset token should only be delivered via the user's verified email address. Returning it in the response allows any caller to immediately reset another user's password.

### Exploitation Scenario
An attacker sends `POST /api/password/forgot` with `{"email": "admin@pipeline.io"}`. The response includes `{"message": "Reset email sent", "token": "a1b2c3d4e5f6g7h8"}`. The attacker uses this token to reset the admin's password and take over the account.

### Remediation Guidance
Send the reset token only via email and never include it in the API response:
```rust
async fn forgot_password(body: web::Json<ForgotRequest>, state: web::Data<AppState>) -> HttpResponse {
    // ... find user, generate token, store it
    // send_email(&user.email, &reset_token);
    HttpResponse::Ok().json(serde_json::json!({"message": "Reset email sent"}))
}
```

### Complexity Rationale
This is rated Obvious because the token is explicitly included in the JSON response object, making the information leak immediately visible in the code.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need data flow analysis to determine that a security-sensitive token generated for password reset flows into the HTTP response body.
