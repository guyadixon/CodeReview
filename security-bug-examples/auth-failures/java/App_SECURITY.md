# Security Companion Document: App.java

## Vulnerability: Hardcoded System API Key and Maintenance Token

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L17-L18  

### Description
The application defines two hardcoded credentials as static final constants: `SYSTEM_API_KEY` and `MAINTENANCE_TOKEN`. The `SYSTEM_API_KEY` is used as a password for a privileged "system" account in the login endpoint, and the `MAINTENANCE_TOKEN` is accepted as a valid token in the validation endpoint. These credentials are embedded in the compiled class file and can be extracted by anyone with access to the JAR or source.

### Exploitation Scenario
An attacker decompiles the application JAR and extracts the value `sys_key_prod_x7y8z9w0`. They send `POST /api/login` with `{"username": "system", "password": "sys_key_prod_x7y8z9w0"}` and receive a valid session token with the "system" role, gaining full privileged access.

### Remediation Guidance
Load credentials from environment variables or a secrets vault:
```java
private static final String SYSTEM_API_KEY = System.getenv("SYSTEM_API_KEY");
private static final String MAINTENANCE_TOKEN = System.getenv("MAINTENANCE_TOKEN");
```

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string constants declared at the class level, immediately visible in the source code or decompiled output.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded string constants in `static final` fields used in authentication comparisons through pattern matching.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L42-L52  

### Description
The `md5Hash` method uses `MessageDigest.getInstance("MD5")` to hash user passwords. MD5 is cryptographically broken for password storage — it is fast, unsalted, and vulnerable to rainbow table and brute force attacks. All user passwords in the static initializer are hashed with this weak function.

### Exploitation Scenario
An attacker who gains access to the user data (via memory dump, debug endpoint, or another vulnerability) obtains MD5 hashes. Using Hashcat or online MD5 lookup services, the attacker reverses hashes like `md5("admin_pass1")` in seconds, recovering plaintext passwords for all accounts.

### Remediation Guidance
Use bcrypt or Argon2 for password hashing:
```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

private static String hashPassword(String input) {
    return encoder.encode(input);
}
```

### Complexity Rationale
This is rated Moderate because the code uses the standard `MessageDigest` API correctly from a functional standpoint. A reviewer must know that MD5 is specifically unsuitable for password hashing despite being a valid hash algorithm.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `MessageDigest.getInstance("MD5")` usage through API pattern matching, especially in authentication-related code paths.

---

## Vulnerability: No Rate Limiting on Login Endpoint

**CWE:** CWE-307  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L72-L97  

### Description
The login endpoint processes unlimited authentication attempts without any rate limiting, account lockout, or progressive delay mechanism. An attacker can perform unrestricted brute force or credential stuffing attacks against any user account.

### Exploitation Scenario
An attacker scripts thousands of `POST /api/login` requests per second targeting the "admin" account with passwords from a leaked credential database. With no throttling or lockout, the attacker eventually discovers the correct password and gains admin access.

### Remediation Guidance
Add rate limiting using Spring Boot's built-in mechanisms or a filter:
```java
@Bean
public FilterRegistrationBean<RateLimitFilter> rateLimitFilter() {
    // Limit login attempts to 5 per minute per IP
}
```

### Complexity Rationale
This is rated Nuanced because the login function itself is correctly implemented with proper credential validation. The vulnerability is the absence of a defensive mechanism rather than a flaw in existing code.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools analyze existing code patterns and generally cannot detect the absence of rate limiting, which is an architectural requirement.

---

## Vulnerability: Hardcoded Maintenance Token Bypasses Authentication

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L101-L103  

### Description
The token validation endpoint accepts the hardcoded `MAINTENANCE_TOKEN` value as a valid authentication token, returning a successful validation with `userId: 0` and `role: maintenance`. This creates a permanent backdoor that bypasses the normal session-based authentication.

### Exploitation Scenario
An attacker who discovers the token value `maint-override-2024` sends `POST /api/auth/validate` with `{"token": "maint-override-2024"}`. The response confirms the token is valid with maintenance-level privileges. Any service relying on this validation endpoint will trust the attacker as a maintenance user.

### Remediation Guidance
Remove the hardcoded token check and use proper service authentication:
```java
@PostMapping("/api/auth/validate")
public ResponseEntity<?> validateToken(@RequestBody Map<String, String> body) {
    String token = body.getOrDefault("token", "");
    Map<String, Object> session = SESSIONS.get(token);
    if (session != null) {
        return ResponseEntity.ok(Map.of("valid", true, "userId", session.get("userId"),
                "role", session.get("role")));
    }
    return ResponseEntity.status(401).body(Map.of("valid", false));
}
```

### Complexity Rationale
This is rated Moderate because the hardcoded check is embedded within a function that also performs legitimate session validation. A reviewer must trace the control flow to notice the special-case bypass.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that comparing a request parameter against a constant in an authentication context constitutes a bypass. Tools with interprocedural constant tracking may detect this.

---

## Vulnerability: Password Reset Token Exposed in API Response

**CWE:** CWE-287  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L117-L122  

### Description
The forgot-password endpoint returns the password reset token directly in the API response alongside the "Reset email sent" message. In production, the reset token should only be delivered via the user's verified email address. Returning it in the response allows any caller to immediately reset another user's password.

### Exploitation Scenario
An attacker sends `POST /api/password/forgot` with `{"email": "admin@buildci.io"}`. The response includes `{"message": "Reset email sent", "token": "a1b2c3d4e5f6g7h8"}`. The attacker uses this token to send `POST /api/password/reset` with a new password, taking over the admin account.

### Remediation Guidance
Send the reset token only via email and never include it in the API response:
```java
@PostMapping("/api/password/forgot")
public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> body) {
    // ... find user, generate token
    emailService.sendResetEmail(user.get("email"), resetToken);
    return ResponseEntity.ok(Map.of("message", "Reset email sent"));
}
```

### Complexity Rationale
This is rated Obvious because the token is explicitly included in the JSON response object, making the information leak immediately visible in the code.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need data flow analysis to determine that a security-sensitive token generated for password reset flows into the HTTP response body.
