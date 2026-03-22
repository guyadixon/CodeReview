# Security Companion Document: main.c

## Vulnerability: Hardcoded Admin API Key and Service Passphrase

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L13-L14  

### Description
The application defines two hardcoded credentials as static string constants: `ADMIN_API_KEY` and `SERVICE_PASSPHRASE`. The API key is used as a password for a privileged "service" account in the login handler, and the passphrase is accepted as a valid token in the verification handler. These values are embedded in the compiled binary and can be extracted with `strings`.

### Exploitation Scenario
An attacker runs `strings auth-server | grep -i key` on the compiled binary and extracts `aak_prod_c4d5e6f7g8h9`. They send `POST /api/login` with `{"username":"service","password":"aak_prod_c4d5e6f7g8h9"}` and receive a session token with the "service" role, gaining privileged access.

### Remediation Guidance
Read credentials from environment variables or a configuration file at runtime:
```c
const char *admin_api_key = getenv("ADMIN_API_KEY");
const char *service_passphrase = getenv("SERVICE_PASSPHRASE");
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string constants at the top of the file, immediately visible in the source code and extractable from the binary.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants used in `strcmp` authentication comparisons through pattern matching.

---

## Vulnerability: Custom Weak Hash Function Used for Password Storage

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L42-L55  

### Description
The `md5_simple` function implements a custom non-cryptographic hash using simple arithmetic operations (addition, XOR, multiplication with magic constants). This is not a real MD5 implementation and provides no cryptographic security guarantees. It is trivially reversible and produces predictable outputs, making password storage fundamentally insecure.

### Exploitation Scenario
An attacker who gains access to the stored password hashes can reverse the custom hash function by analyzing its simple arithmetic operations. Since the function uses no salt and has a small effective output space, the attacker can build a lookup table or directly reverse the hash to recover plaintext passwords.

### Remediation Guidance
Use a proper password hashing library such as libsodium's `crypto_pwhash`:
```c
#include <sodium.h>

char hashed[crypto_pwhash_STRBYTES];
crypto_pwhash_str(hashed, password, strlen(password),
    crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
```

### Complexity Rationale
This is rated Moderate because the function is named `md5_simple` which may mislead a reviewer into thinking it provides MD5-level security. A reviewer must examine the implementation to realize it is a custom non-cryptographic hash.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools would need to analyze the hash function implementation to determine it is not a standard cryptographic algorithm. Tools that only check for known API calls (like `MD5()`) would miss this custom implementation.

---

## Vulnerability: No Rate Limiting on Login Endpoint

**CWE:** CWE-307  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L152-L184  

### Description
The login handler processes unlimited authentication attempts without any rate limiting, account lockout, or delay mechanism. An attacker can perform unrestricted brute force or credential stuffing attacks against any user account.

### Exploitation Scenario
An attacker scripts thousands of `POST /api/login` requests per second targeting the "admin" account with passwords from a common password list. With no throttling or lockout, the attacker eventually discovers the correct password and gains admin access.

### Remediation Guidance
Implement per-IP rate limiting by tracking connection attempts:
```c
// Track failed attempts per IP address
// Block IP after 5 failed attempts within 60 seconds
```

### Complexity Rationale
This is rated Nuanced because the login handler itself is correctly implemented with proper credential validation. The vulnerability is the absence of a defensive mechanism rather than a flaw in existing code.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools analyze existing code and generally cannot detect the absence of rate limiting logic in authentication handlers.

---

## Vulnerability: Hardcoded Service Passphrase Bypasses Token Verification

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L189-L192  

### Description
The token verification handler accepts the hardcoded `SERVICE_PASSPHRASE` value as a valid authentication token, returning a successful verification with `userId: 0` and `role: service`. This creates a permanent backdoor that bypasses the normal session-based authentication flow.

### Exploitation Scenario
An attacker who discovers the value `svc-auth-bypass-2024` sends `POST /api/auth/verify` with `{"token":"svc-auth-bypass-2024"}`. The response confirms the token is valid with service-level privileges. Any downstream service relying on this verification endpoint will trust the attacker.

### Remediation Guidance
Remove the hardcoded passphrase check from the verification handler and rely solely on session-based validation.

### Complexity Rationale
This is rated Moderate because the hardcoded check is embedded within a function that also performs legitimate session validation. A reviewer must trace the control flow to notice the special-case bypass.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that a `strcmp` against a constant in an authentication verification function constitutes a bypass.

---

## Vulnerability: Password Reset Token Exposed in API Response

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L224-L228  

### Description
The forgot-password handler returns the password reset token directly in the API response via `snprintf` into the JSON response buffer. In production, the reset token should only be delivered via the user's verified email address. Returning it in the response allows any caller to immediately reset another user's password.

### Exploitation Scenario
An attacker sends `POST /api/password/forgot` with `{"email":"admin@netmon.io"}`. The response includes the reset token in the JSON body. The attacker uses this token to send `POST /api/password/reset` with a new password, taking over the admin account.

### Remediation Guidance
Send the reset token only via email and return only a confirmation message:
```c
snprintf(buf, sizeof(buf), "{\"message\":\"Reset email sent\"}");
```

### Complexity Rationale
This is rated Obvious because the token is explicitly formatted into the JSON response string, making the information leak immediately visible in the code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the reset token variable flows directly into the `snprintf` call that builds the HTTP response, a data flow pattern that SAST tools can trace.
