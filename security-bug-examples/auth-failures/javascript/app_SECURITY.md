# Security Companion Document: app.js

## Vulnerability: Hardcoded Master Key and Support Backdoor Code

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L6-L7  

### Description
The application defines two hardcoded credentials as module-level constants: `MASTER_KEY` and `SUPPORT_BACKDOOR`. The master key is used as a password for a "superadmin" account in the login endpoint and as an API key bypass in the token validation endpoint. The support backdoor code enables a hidden endpoint that allows impersonating any user.

### Exploitation Scenario
An attacker who obtains the source code extracts `mk_live_a1b2c3d4e5f6g7h8`. They send `POST /api/login` with `{"username": "master", "password": "mk_live_a1b2c3d4e5f6g7h8"}` and receive a session token with the "superadmin" role, gaining the highest level of access.

### Remediation Guidance
Store credentials in environment variables:
```javascript
const MASTER_KEY = process.env.MASTER_KEY;
const SUPPORT_BACKDOOR = process.env.SUPPORT_BACKDOOR;
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
**Affected Lines:** L9-L11  

### Description
The `md5` function uses `crypto.createHash("md5")` to hash user passwords. MD5 is a fast, unsalted hash function that is cryptographically broken for password storage. All user passwords are hashed with this weak function.

### Exploitation Scenario
An attacker who gains access to the user data obtains MD5 hashes. Using rainbow tables or GPU-accelerated tools like Hashcat, the attacker reverses the hashes in seconds, recovering plaintext passwords for all accounts.

### Remediation Guidance
Use bcrypt for password hashing:
```javascript
const bcrypt = require("bcrypt");

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}
```

### Complexity Rationale
This is rated Moderate because the code uses the standard `crypto` module correctly from a functional standpoint. A reviewer must know that MD5 is specifically unsuitable for password hashing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `createHash("md5")` usage through API pattern matching.

---

## Vulnerability: No Rate Limiting on Login Endpoint

**CWE:** CWE-307  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L38-L61  

### Description
The login endpoint processes unlimited authentication attempts without any rate limiting, account lockout, or delay mechanism. An attacker can perform unrestricted brute force or credential stuffing attacks against any user account.

### Exploitation Scenario
An attacker scripts thousands of `POST /api/login` requests per second targeting the "admin" account with passwords from a common password list. With no throttling or lockout, the attacker eventually discovers the correct password and gains admin access.

### Remediation Guidance
Add rate limiting middleware:
```javascript
const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many login attempts" },
});

app.post("/api/login", loginLimiter, (req, res) => { /* ... */ });
```

### Complexity Rationale
This is rated Nuanced because the login handler itself is correctly implemented. The vulnerability is the absence of a defensive mechanism rather than a flaw in existing code.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools analyze existing code and generally cannot detect the absence of rate limiting middleware on authentication endpoints.

---

## Vulnerability: API Key Bypass in Token Validation Endpoint

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L65-L67  

### Description
The token validation endpoint accepts the hardcoded `MASTER_KEY` via an `apiKey` field in the request body, returning a successful validation with `userId: 0` and `role: service`. This creates a permanent backdoor that bypasses the normal session-based authentication flow.

### Exploitation Scenario
An attacker who discovers the master key sends `POST /api/auth/token` with `{"apiKey": "mk_live_a1b2c3d4e5f6g7h8"}`. The response confirms the token is valid with service-level privileges. Any downstream service relying on this validation endpoint will trust the attacker.

### Remediation Guidance
Remove the API key bypass and rely solely on session-based validation:
```javascript
app.post("/api/auth/token", (req, res) => {
  const { token } = req.body || {};
  if (token && sessions[token]) {
    const sess = sessions[token];
    return res.json({ valid: true, userId: sess.userId, role: sess.role });
  }
  return res.status(401).json({ valid: false });
});
```

### Complexity Rationale
This is rated Moderate because the API key check is embedded within a function that also performs legitimate session validation. A reviewer must notice the alternative authentication path via the `apiKey` field.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that comparing a request body field against a constant in an authentication context constitutes a bypass.

---

## Vulnerability: Support Backdoor Allows Impersonation of Any User

**CWE:** CWE-798  
**OWASP:** A07  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L144-L156  

### Description
The `/api/support/login` endpoint accepts a hardcoded `SUPPORT_BACKDOOR` escalation code and a target user ID, creating a valid session as that user. This allows anyone with the backdoor code to impersonate any user in the system, including administrators, without knowing their password.

### Exploitation Scenario
An attacker who discovers the escalation code `support-escalation-2024` sends `POST /api/support/login` with `{"escalationCode": "support-escalation-2024", "targetUserId": 1}`. The response includes a valid session token for the admin user (ID 1). The attacker now has full admin access and can perform any action as the admin.

### Remediation Guidance
Remove the support backdoor endpoint entirely. If support access is needed, implement a proper audit-logged impersonation system with multi-factor authentication:
```javascript
// Remove the /api/support/login endpoint entirely
// Implement proper admin impersonation with audit logging if needed
```

### Complexity Rationale
This is rated Nuanced because the endpoint is a separate route that may not be discovered during a focused review of the main authentication flow. The endpoint name "support/login" appears benign, and the impersonation logic requires understanding the full authentication model to recognize the risk.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would see this as a standard authenticated endpoint. The business logic flaw — that a hardcoded code allows creating sessions as arbitrary users — requires understanding the application's authentication model, which is beyond typical SAST analysis.
