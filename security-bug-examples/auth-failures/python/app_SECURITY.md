# Security Companion Document: app.py

## Vulnerability: Hardcoded Service API Key Enables Authentication Bypass

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L25-L26  

### Description
The application defines two hardcoded credentials as module-level constants: `SERVICE_API_KEY` and `INTERNAL_GATEWAY_TOKEN`. The `SERVICE_API_KEY` is used as a password for a special "service" account in the login endpoint, and the `INTERNAL_GATEWAY_TOKEN` is accepted as a valid token in the verification endpoint. Anyone with access to the source code or binary can extract these credentials and gain privileged access.

### Exploitation Scenario
An attacker who obtains the source code (via repository access, leaked deployment artifact, or decompilation) extracts the value `ak_prod_9f8e7d6c5b4a3210`. They send `POST /api/login` with `{"username": "service", "password": "ak_prod_9f8e7d6c5b4a3210"}` and receive a valid session token with the "service" role, bypassing normal user authentication entirely.

### Remediation Guidance
Store credentials in environment variables or a secrets manager and never embed them in source code:
```python
import os

SERVICE_API_KEY = os.environ.get("SERVICE_API_KEY")
INTERNAL_GATEWAY_TOKEN = os.environ.get("INTERNAL_GATEWAY_TOKEN")
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string constants assigned to clearly named variables, immediately visible to anyone reading the code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants used in authentication comparisons through simple pattern matching on credential-like variable names and string literals.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L10-L21  

### Description
The application uses MD5 (`hashlib.md5`) to hash user passwords throughout the USERS dictionary initialization. MD5 is a fast, non-salted hash function that is cryptographically broken for password storage. Precomputed rainbow tables and GPU-accelerated brute force attacks can reverse MD5 password hashes in seconds.

### Exploitation Scenario
An attacker who gains access to the in-memory user data (via another vulnerability or memory dump) obtains MD5 hashes of all user passwords. Using publicly available rainbow tables or a tool like Hashcat, the attacker cracks the hashes within minutes, recovering plaintext passwords such as "admin123" and "john2024!".

### Remediation Guidance
Use a purpose-built password hashing algorithm with salting and configurable work factor:
```python
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())
```

### Complexity Rationale
This is rated Moderate because while MD5 is widely known to be insecure, the code uses the standard `hashlib` library in a way that appears functional. A reviewer must know that MD5 is inappropriate specifically for password hashing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `hashlib.md5` usage in authentication contexts through straightforward API pattern matching.

---

## Vulnerability: No Rate Limiting on Login Endpoint

**CWE:** CWE-307  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L47-L69  

### Description
The login endpoint accepts unlimited authentication attempts without any rate limiting, account lockout, or delay mechanism. An attacker can perform unrestricted brute force or credential stuffing attacks against any user account.

### Exploitation Scenario
An attacker targets the "admin" account by sending thousands of `POST /api/login` requests per second with different passwords from a common password list. With no rate limiting or lockout, the attacker eventually discovers the password "admin123" and gains admin access to the system.

### Remediation Guidance
Implement rate limiting and account lockout:
```python
from flask_limiter import Limiter

limiter = Limiter(app, default_limits=["100 per hour"])

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # ... existing logic
    # Also track failed attempts per account and lock after N failures
```

### Complexity Rationale
This is rated Nuanced because the absence of rate limiting is not a code-level flaw but an architectural omission. The login function itself is correctly implemented; the vulnerability is in what is missing rather than what is present.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools analyze code that exists, not code that is absent. Detecting missing rate limiting requires understanding that login endpoints should have throttling, which is a business logic requirement.

---

## Vulnerability: Hardcoded Gateway Token Accepted as Valid Authentication

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L79-L80  

### Description
The token verification endpoint accepts the hardcoded `INTERNAL_GATEWAY_TOKEN` value as a valid authentication token, returning a successful verification with `user_id: 0` and `role: gateway`. This creates a permanent backdoor that bypasses the normal session-based authentication flow.

### Exploitation Scenario
An attacker who discovers the token value `gw-internal-2024-prod` can send `POST /api/verify` with `{"token": "gw-internal-2024-prod"}` and receive a response confirming the token is valid with gateway-level privileges. Any downstream service that relies on this verification endpoint will trust the attacker as an internal gateway.

### Remediation Guidance
Remove hardcoded token acceptance and use proper service-to-service authentication:
```python
@app.route("/api/verify", methods=["POST"])
def verify_token():
    data = request.get_json()
    token = data.get("token", "") if data else ""
    if token in SESSIONS:
        session = SESSIONS[token]
        return jsonify({"valid": True, "user_id": session["user_id"]})
    return jsonify({"valid": False}), 401
```

### Complexity Rationale
This is rated Moderate because the hardcoded token check is embedded within a function that also performs legitimate session validation. A reviewer must trace the control flow to notice the special-case bypass after the normal session lookup.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that a constant string comparison in an authentication verification function constitutes a bypass. Tools that track taint flow from constants to authentication decisions may catch this.

---

## Vulnerability: Password Reset Token Leaked in API Response

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L89-L91  

### Description
The password reset endpoint returns the reset token directly in the API response as `debug_token`. In a production system, the reset token should only be sent via email to the account owner. Exposing it in the response allows any caller to immediately use the token to reset another user's password.

### Exploitation Scenario
An attacker sends `POST /api/password-reset` with `{"email": "admin@acmecorp.io"}`. The response includes `{"message": "Reset link sent", "debug_token": "a1b2c3d4e5f6g7h8"}`. The attacker then sends `POST /api/password-reset/confirm` with the token and a new password, taking over the admin account without access to the admin's email.

### Remediation Guidance
Never return the reset token in the API response; send it only via the user's verified email:
```python
@app.route("/api/password-reset", methods=["POST"])
def request_password_reset():
    # ... find user by email
    reset_token = generate_secure_token()
    send_email(user["email"], reset_token)
    return jsonify({"message": "Reset link sent"})
```

### Complexity Rationale
This is rated Moderate because the token is returned under a field named `debug_token`, which might appear intentional for development but is a serious flaw in production. A reviewer must recognize that exposing reset tokens in responses defeats the purpose of email-based verification.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand that password reset tokens are sensitive values that should not appear in HTTP responses. Tools with data flow analysis may flag the token flowing from generation to response body.
