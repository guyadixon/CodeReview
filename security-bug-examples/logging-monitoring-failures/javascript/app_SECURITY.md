# Security Companion Document: app.js

## Vulnerability: No Logging of Failed Authentication Attempts

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L52-L68  

### Description
The login endpoint returns 401 and 403 responses for invalid credentials and disabled accounts but does not log any failed authentication attempts. The Express.js application has no logging middleware (such as winston or morgan with custom formatters) and no `console.log` calls in the authentication flow beyond the server startup message.

### Exploitation Scenario
An attacker runs a credential stuffing tool against `/api/login` with thousands of stolen username/password pairs. Every failed attempt returns a 401 response but generates no log entry. The operations team has no visibility into the attack and no ability to trigger alerts.

### Remediation Guidance
Add structured logging for failed authentication:
```javascript
const winston = require("winston");
const logger = winston.createLogger({ /* ... */ });

// On failed login:
logger.warn("Failed login attempt", { username, ip: req.ip });
```

### Complexity Rationale
This is rated Obvious because the complete absence of any logging library import or logging call in the authentication handler is immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can check for the absence of logging calls in authentication handlers. Rules that flag login endpoints without logger calls can catch this directly.

---

## Vulnerability: No Logging of Successful Authentication Events

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L63-L72  

### Description
When authentication succeeds, the endpoint returns a session token along with the user's plaintext password and API key but generates no log entry. Successful login logging is essential for detecting account takeover and building user activity baselines.

### Exploitation Scenario
An attacker who has obtained valid credentials through phishing logs in successfully. The legitimate account owner and security team have no record of the unauthorized login session. The attacker operates under the compromised account indefinitely.

### Remediation Guidance
Log successful authentication events:
```javascript
logger.info("Successful login", { username: user.username, userId: user.id, ip: req.ip });
```

### Complexity Rationale
This is rated Moderate because developers often focus on logging failures rather than successes. A reviewer must understand that successful login logging is equally important for detecting unauthorized access.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand Express.js route handler patterns and identify that the successful authentication code path lacks logging.

---

## Vulnerability: No Audit Logging for Privilege Escalation Operations

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L89-L110  

### Description
The role change endpoint (`PUT /api/admin/users/:id/role`) modifies user privileges without logging who made the change, what the old and new roles are, or when the change occurred. Any authenticated user can change any other user's role without admin verification, and the change leaves no trace.

### Exploitation Scenario
A compromised developer account changes its own role to `admin`. Without audit logging, the privilege escalation is invisible. The attacker then uses admin privileges to deactivate other accounts and exfiltrate data.

### Remediation Guidance
Log all privilege changes:
```javascript
logger.warn("Role change", { targetId, oldRole, newRole: role, callerId: session.userId, ip: req.ip });
```

### Complexity Rationale
This is rated Moderate because role changes are clearly security-sensitive operations, but the reviewer must recognize that the absence of audit logging is a distinct vulnerability.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that a role-change endpoint requires audit logging. This is a business logic requirement.

---

## Vulnerability: No Logging of Financial Transactions

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L127-L172  

### Description
Both the single transaction and bulk transfer endpoints process financial operations without any server-side logging. Transactions are pushed to an in-memory array, but there is no persistent audit log, no logging of amounts or recipients, and no alerting mechanism for unusual transaction patterns.

### Exploitation Scenario
An attacker with a compromised session token initiates a series of high-value bulk transfers. Because no transaction logging exists, the fraud goes undetected until financial reconciliation discovers the discrepancy.

### Remediation Guidance
Log all financial transactions:
```javascript
logger.info("Transaction created", { id: transaction.id, userId: session.userId, amount, recipient, ip: req.ip });
```

### Complexity Rationale
This is rated Nuanced because the transactions are stored in an array, which may give a false sense of record-keeping. A reviewer must distinguish between application data storage and security audit logging.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that a transaction endpoint requires audit logging based on the business context.

---

## Vulnerability: No Logging of Sensitive Data Export

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L174-L198  

### Description
The data export endpoint allows any authenticated user to export all user records (including passwords and API keys) or all transactions without logging who requested the export. Mass data exfiltration through this endpoint leaves no audit trail.

### Exploitation Scenario
An insider exports the complete user database including plaintext passwords and API keys via `POST /api/export/data {"type": "users"}`. No log entry records this mass data exfiltration. The insider uses the harvested credentials to compromise additional accounts.

### Remediation Guidance
Log all data export operations:
```javascript
logger.warn("Data export requested", { type, userId: session.userId, ip: req.ip });
```

### Complexity Rationale
This is rated Moderate because data export endpoints are recognized as high-risk operations that should be audited.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially identify export endpoints by naming conventions and flag the absence of logging.

---

## Vulnerability: No Logging of Security Configuration Changes

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L200-L234  

### Description
The API key regeneration and MFA toggle endpoints modify security-critical account settings without any logging. Regenerating an API key invalidates the previous key, and disabling MFA weakens account security. Neither operation produces any audit log entry.

### Exploitation Scenario
An attacker with a compromised session disables MFA on the admin account and regenerates the API key. The legitimate admin discovers their API key no longer works but has no log trail to determine when or how the change occurred.

### Remediation Guidance
Log all security configuration changes:
```javascript
logger.warn("API key regenerated", { userId: session.userId, ip: req.ip });
logger.warn("MFA toggled", { userId: session.userId, enabled, ip: req.ip });
```

### Complexity Rationale
This is rated Nuanced because API key rotation and MFA management are not always recognized as security-critical operations requiring audit logging.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that MFA and API key endpoints are security-sensitive operations requiring logging.
