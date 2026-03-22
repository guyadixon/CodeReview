# Security Companion Document: main.cpp

## Vulnerability: Hardcoded Operator Key and Monitoring Token

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L15-L16  

### Description
The application defines two hardcoded credentials as static constants: `OPERATOR_KEY` and `MONITORING_TOKEN`. The operator key is used as a password for a privileged "operator" account in the login handler, and the monitoring token is accepted as a valid token in the verification handler. These values are embedded in the compiled binary and can be extracted with `strings`.

### Exploitation Scenario
An attacker runs `strings auth-server | grep -i key` on the compiled binary and extracts `opk_prod_2024_a1b2c3d4`. They send `POST /api/login` with `{"username":"operator","password":"opk_prod_2024_a1b2c3d4"}` and receive a session token with the "operator" role, gaining privileged access.

### Remediation Guidance
Read credentials from environment variables at runtime:
```cpp
static const std::string OPERATOR_KEY = std::getenv("OPERATOR_KEY") ? std::getenv("OPERATOR_KEY") : "";
static const std::string MONITORING_TOKEN = std::getenv("MONITORING_TOKEN") ? std::getenv("MONITORING_TOKEN") : "";
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string constants at the top of the file, immediately visible in the source code and extractable from the binary.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants used in authentication comparisons through pattern matching.

---

## Vulnerability: std::hash Used for Password Storage

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L41-L50  

### Description
The `simple_hash` function uses `std::hash<std::string>` to hash user passwords. `std::hash` is a non-cryptographic hash function designed for hash tables, not for security purposes. It provides no collision resistance guarantees, uses no salt, and its output can be reversed or collided trivially. The function attempts to strengthen the hash by concatenating two `std::hash` outputs, but this does not provide cryptographic security.

### Exploitation Scenario
An attacker who gains access to the stored password hashes can reverse the `std::hash` function or find collisions using its known algorithm. Since `std::hash` implementations are deterministic and often simple (e.g., FNV-1a), the attacker can build a lookup table or brute-force passwords efficiently.

### Remediation Guidance
Use a proper password hashing library such as bcrypt via a C++ wrapper:
```cpp
#include <bcrypt/BCrypt.hpp>

std::string hash_password(const std::string& password) {
    return BCrypt::generateHash(password);
}
```

### Complexity Rationale
This is rated Nuanced because `std::hash` is a standard library function that appears legitimate. The function name `simple_hash` and the double-hashing pattern may mislead a reviewer into thinking it provides adequate security. Understanding that `std::hash` is non-cryptographic requires specific C++ knowledge.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically flag known weak cryptographic APIs (like MD5 or SHA1) but may not recognize `std::hash` as inappropriate for password storage since it is not a cryptographic function at all.

---

## Vulnerability: No Rate Limiting on Login Endpoint

**CWE:** CWE-307  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L88-L126  

### Description
The login handler processes unlimited authentication attempts without any rate limiting, account lockout, or delay mechanism. An attacker can perform unrestricted brute force or credential stuffing attacks against any user account.

### Exploitation Scenario
An attacker scripts thousands of `POST /api/login` requests per second targeting the "admin" account with passwords from a common password list. With no throttling or lockout, the attacker eventually discovers the correct password and gains admin access.

### Remediation Guidance
Implement per-IP rate limiting by tracking connection attempts with timestamps and blocking IPs that exceed a threshold.

### Complexity Rationale
This is rated Nuanced because the login handler itself is correctly implemented with proper credential validation. The vulnerability is the absence of a defensive mechanism rather than a flaw in existing code.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools analyze existing code and generally cannot detect the absence of rate limiting logic in authentication handlers.

---

## Vulnerability: Hardcoded Monitoring Token Bypasses Authentication

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L137-L140  

### Description
The token verification handler accepts the hardcoded `MONITORING_TOKEN` value as a valid authentication token, returning a successful verification with `userId: 0` and `role: monitoring`. This creates a permanent backdoor that bypasses the normal session-based authentication flow.

### Exploitation Scenario
An attacker who discovers the value `mon-internal-auth-2024` sends `POST /api/auth/verify` with `{"token":"mon-internal-auth-2024"}`. The response confirms the token is valid with monitoring-level privileges. Any downstream service relying on this verification endpoint will trust the attacker.

### Remediation Guidance
Remove the hardcoded token check and rely solely on session-based validation.

### Complexity Rationale
This is rated Moderate because the hardcoded check is embedded within a function that also performs legitimate session validation. A reviewer must trace the control flow to notice the special-case bypass.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that comparing a request parameter against a constant in an authentication context constitutes a bypass.

---

## Vulnerability: Password Reset Token Exposed in API Response

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L169-L172  

### Description
The forgot-password handler returns the password reset token directly in the API response. In production, the reset token should only be delivered via the user's verified email address. Returning it in the response allows any caller to immediately reset another user's password.

### Exploitation Scenario
An attacker sends `POST /api/password/forgot` with `{"email":"admin@logvault.io"}`. The response includes the reset token in the JSON body. The attacker uses this token to reset the admin's password and take over the account.

### Remediation Guidance
Return only a confirmation message without the token:
```cpp
json resp = {{"message", "Reset email sent"}};
res.set_content(resp.dump(), "application/json");
```

### Complexity Rationale
This is rated Obvious because the token is explicitly included in the JSON response object, making the information leak immediately visible in the code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the reset token variable flows directly into the JSON response construction, a data flow pattern that SAST tools can trace.
