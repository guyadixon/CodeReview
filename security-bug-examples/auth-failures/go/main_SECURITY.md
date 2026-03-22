# Security Companion Document: main.go

## Vulnerability: Hardcoded Internal API Key and Debug Access Code

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L18-L19  

### Description
The application defines two hardcoded credentials as package-level constants: `internalAPIKey` and `debugAccessCode`. The `internalAPIKey` is used as a password for a privileged "internal" account in the login endpoint and as an API key for the debug sessions endpoint. The `debugAccessCode` is accepted as a valid token in the verification endpoint. These values are embedded in the compiled binary.

### Exploitation Scenario
An attacker who obtains the source code or reverse-engineers the binary extracts `iak_prod_7f3e2d1c0b9a8`. They send `POST /api/login` with `{"username": "internal", "password": "iak_prod_7f3e2d1c0b9a8"}` and receive a session token with the "internal" role, gaining privileged access to the system.

### Remediation Guidance
Load credentials from environment variables:
```go
var (
    internalAPIKey  = os.Getenv("INTERNAL_API_KEY")
    debugAccessCode = os.Getenv("DEBUG_ACCESS_CODE")
)
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string constants at the package level, immediately visible to anyone reading the source code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants used in authentication comparisons through pattern matching on credential-like variable names.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L47-L50  

### Description
The `md5Hash` function uses `crypto/md5` to hash user passwords. MD5 is a fast, unsalted hash function that is cryptographically broken for password storage. All user passwords in the `init` function are hashed with this weak function.

### Exploitation Scenario
An attacker who gains access to the user data obtains MD5 hashes. Using rainbow tables or GPU-accelerated tools like Hashcat, the attacker reverses the hashes in seconds, recovering plaintext passwords for all accounts.

### Remediation Guidance
Use bcrypt for password hashing:
```go
import "golang.org/x/crypto/bcrypt"

func hashPassword(password string) string {
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hash)
}
```

### Complexity Rationale
This is rated Moderate because the code uses the standard `crypto/md5` package correctly from a functional standpoint. A reviewer must know that MD5 is specifically unsuitable for password hashing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools like gosec can flag `crypto/md5` usage through API pattern matching.

---

## Vulnerability: No Rate Limiting on Login Endpoint

**CWE:** CWE-307  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L98-L135  

### Description
The login handler processes unlimited authentication attempts without any rate limiting, account lockout, or delay mechanism. An attacker can perform unrestricted brute force or credential stuffing attacks against any user account.

### Exploitation Scenario
An attacker scripts thousands of `POST /api/login` requests per second targeting the "admin" account with passwords from a common password list. With no throttling or lockout, the attacker eventually discovers the correct password and gains admin access.

### Remediation Guidance
Add rate limiting middleware:
```go
import "github.com/ulule/limiter/v3"

// Configure 5 requests per minute per IP for login
```

### Complexity Rationale
This is rated Nuanced because the login handler itself is correctly implemented. The vulnerability is the absence of a defensive mechanism rather than a flaw in existing code.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools analyze existing code and generally cannot detect the absence of rate limiting middleware on authentication endpoints.

---

## Vulnerability: Hardcoded Debug Access Code Bypasses Token Verification

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L146-L148  

### Description
The token verification endpoint accepts the hardcoded `debugAccessCode` value as a valid authentication token, returning a successful verification with `userId: 0` and `role: debug`. This creates a permanent backdoor that bypasses the normal session-based authentication flow.

### Exploitation Scenario
An attacker who discovers the value `debug-access-2024-prod` sends `POST /api/auth/verify` with `{"token": "debug-access-2024-prod"}`. The response confirms the token is valid with debug-level privileges. Any downstream service relying on this verification endpoint will trust the attacker.

### Remediation Guidance
Remove the hardcoded token check from the verification endpoint:
```go
func handleVerifyToken(c *gin.Context) {
    var body struct { Token string `json:"token"` }
    c.ShouldBindJSON(&body)
    mu.RLock()
    sess := sessions[body.Token]
    mu.RUnlock()
    if sess != nil {
        c.JSON(200, gin.H{"valid": true, "userId": sess.UserID, "role": sess.Role})
        return
    }
    c.JSON(401, gin.H{"valid": false})
}
```

### Complexity Rationale
This is rated Moderate because the hardcoded check is embedded within a function that also performs legitimate session validation. A reviewer must trace the control flow to notice the special-case bypass before the normal session lookup.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that comparing a request parameter against a constant in an authentication context constitutes a bypass.

---

## Vulnerability: Debug Endpoint Exposes Active Session Tokens

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L301-L321  

### Description
The `/api/debug/sessions` endpoint returns all active session tokens, user IDs, roles, and creation times. While it requires the internal API key header, the endpoint exposes session tokens that can be used to hijack any active user session. The API key itself is hardcoded, compounding the risk.

### Exploitation Scenario
An attacker who knows the hardcoded `internalAPIKey` sends `GET /api/debug/sessions` with the `X-Api-Key` header. The response contains all active session tokens. The attacker picks an admin session token and uses it in subsequent requests to impersonate the admin user.

### Remediation Guidance
Remove the debug endpoint from production code, or at minimum never expose raw session tokens:
```go
func handleDebugSessions(c *gin.Context) {
    // Only show session count, not actual tokens
    c.JSON(200, gin.H{"total": len(sessions)})
}
```

### Complexity Rationale
This is rated Moderate because the endpoint does require an API key, which may give a false sense of security. A reviewer must recognize that the API key is hardcoded and that exposing session tokens enables session hijacking.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand that session tokens are sensitive data that should not be returned in API responses, and that the API key protection is insufficient due to being hardcoded.
