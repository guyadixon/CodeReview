# Security Companion Document: App.java

## Vulnerability: No Logging of Failed Authentication Attempts

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L86-L99  

### Description
The login endpoint handles invalid credentials and disabled accounts by returning HTTP error responses but does not log any failed authentication attempts. The Spring Boot application has no logging framework calls anywhere in the authentication flow. Without logging, brute-force attacks and credential stuffing campaigns generate no alerts.

### Exploitation Scenario
An attacker uses automated tools to attempt thousands of credential combinations against `/api/login`. Each failed attempt returns a 401 response but produces no log entry. The security team has no visibility into the attack volume, targeted usernames, or source IP addresses.

### Remediation Guidance
Add SLF4J logging for failed authentication:
```java
private static final Logger logger = LoggerFactory.getLogger(App.class);

// On failed login:
logger.warn("Failed login attempt for user={} from ip={}", username, request.getRemoteAddr());
```

### Complexity Rationale
This is rated Obvious because the complete absence of any Logger declaration or logging call in the entire class is immediately visible. Spring Boot includes SLF4J by default, making the omission conspicuous.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can check for the absence of logging statements in authentication handlers. Rules that flag `@PostMapping` login endpoints without logger calls can catch this directly.

---

## Vulnerability: No Logging of Successful Authentication Events

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L89-L96  

### Description
When authentication succeeds, the endpoint returns a session token along with the user's password and API key in the response body, but generates no log entry. Successful login events are critical for detecting account takeover and building user activity baselines.

### Exploitation Scenario
An attacker who has obtained valid credentials through phishing logs in successfully. The legitimate account owner and security team have no record of the unauthorized login session. The attacker maintains persistent access without detection.

### Remediation Guidance
Log successful authentication events:
```java
logger.info("Successful login for user={} (id={}) from ip={}", username, userId, request.getRemoteAddr());
```

### Complexity Rationale
This is rated Moderate because developers often focus on logging failures rather than successes. A reviewer must understand that successful login logging is equally important for detecting unauthorized access.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand Spring Boot controller patterns and identify that the successful authentication code path lacks logging calls.

---

## Vulnerability: No Audit Logging for Privilege Escalation Operations

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L118-L138  

### Description
The role change endpoint (`PUT /api/admin/users/{userId}/role`) modifies user privileges without any audit logging. The endpoint does not verify that the caller has admin privileges, and the role change leaves no trace in any log. This allows silent privilege escalation.

### Exploitation Scenario
A compromised developer account sends a PUT request to change its own role to `admin`. Without audit logging, the privilege escalation is invisible. The attacker then uses admin access to deactivate other accounts and exfiltrate data.

### Remediation Guidance
Log all privilege changes:
```java
logger.warn("Role change: userId={} from '{}' to '{}' by callerId={}", userId, oldRole, newRole, session.get("user_id"));
```

### Complexity Rationale
This is rated Moderate because role changes are clearly security-sensitive operations, but the reviewer must recognize that the absence of logging on this endpoint is a distinct vulnerability from the missing authorization check.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that a role-change endpoint requires audit logging. This is a business logic requirement.

---

## Vulnerability: No Logging of Bulk Financial Transactions

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L170-L199  

### Description
Both the single transaction and bulk transfer endpoints process financial operations without any logging. The bulk transfer endpoint is particularly concerning as it allows processing an unlimited number of transfers in a single request with no audit trail, rate limiting, or anomaly detection.

### Exploitation Scenario
An attacker with a compromised session submits a bulk transfer request with hundreds of high-value transactions. The transfers complete silently without any log entries. By the time the fraud is discovered through financial reconciliation, the attacker has moved funds through multiple accounts.

### Remediation Guidance
Log all financial transactions:
```java
logger.info("Transaction: id={} userId={} amount={} recipient={}", tx.get("id"), session.get("user_id"), amount, recipient);
logger.info("Bulk transfer: {} transactions by userId={}", results.size(), session.get("user_id"));
```

### Complexity Rationale
This is rated Nuanced because the transactions are stored in an in-memory list, which may appear to provide record-keeping. A reviewer must distinguish between application data storage and security audit logging with alerting capabilities.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that financial transaction endpoints require audit logging. This depends on understanding the business context of the operations.

---

## Vulnerability: No Logging of Sensitive Data Export

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L201-L228  

### Description
The data export endpoint allows any authenticated user to export all user records including plaintext passwords and API keys, or all transaction records, without logging who requested the export. Mass data exfiltration through this endpoint leaves no audit trail.

### Exploitation Scenario
An insider exports the complete user database including passwords and API keys. No log entry records this bulk data access. The insider sells the credentials on the dark web, and the breach is only discovered when users report account compromises on other services.

### Remediation Guidance
Log all data export operations:
```java
logger.warn("Data export: type={} by userId={}", exportType, session.get("user_id"));
```

### Complexity Rationale
This is rated Moderate because data export endpoints are recognized as high-risk operations. The endpoint name `/api/export/data` clearly indicates bulk data access that should be audited.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially identify export endpoints by naming conventions and flag the absence of logging, but this requires understanding Spring Boot controller patterns.

---

## Vulnerability: No Logging of Security Configuration Changes

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L230-L270  

### Description
The API key regeneration and MFA toggle endpoints modify security-critical account settings without any logging. Regenerating an API key invalidates the previous key, and disabling MFA weakens account security. Neither operation produces any audit log entry.

### Exploitation Scenario
An attacker with a compromised session disables MFA on the admin account and regenerates the API key. The legitimate admin discovers their API key no longer works but has no log trail to determine when or how the change occurred. The attacker uses the new API key for persistent access.

### Remediation Guidance
Log all security configuration changes:
```java
logger.warn("API key regenerated: userId={}", session.get("user_id"));
logger.warn("MFA toggled: userId={} enabled={}", session.get("user_id"), enabled);
```

### Complexity Rationale
This is rated Nuanced because API key rotation and MFA management are not always recognized as security-critical operations requiring audit logging. A reviewer must understand that changes to authentication factors are high-impact events.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that MFA and API key endpoints are security-sensitive operations requiring logging. These are business logic requirements.
