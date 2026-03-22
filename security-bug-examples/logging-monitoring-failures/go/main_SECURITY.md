# Security Companion Document: main.go

## Vulnerability: No Logging of Failed Authentication Attempts

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L97-L113  

### Description
The login handler returns 401 and 403 responses for invalid credentials and disabled accounts but does not log any failed authentication attempts. The application uses Gin's default logger middleware for request access logs, but these do not capture authentication-specific context such as the targeted username or failure reason.

### Exploitation Scenario
An attacker runs a credential stuffing campaign against `/api/login`. Gin's access log shows POST requests returning 401, but without structured authentication logging, the security team cannot correlate attacks by username, detect targeted accounts, or trigger automated lockout policies.

### Remediation Guidance
Add structured logging for failed authentication:
```go
import "log"

// On failed login:
log.Printf("WARN: Failed login attempt for user=%s from ip=%s", body.Username, c.ClientIP())
```

### Complexity Rationale
This is rated Obvious because the absence of any `log` package import or logging call in the authentication handler is immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can check for the absence of logging calls in authentication handlers and flag login endpoints without log statements.

---

## Vulnerability: No Logging of Successful Authentication Events

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L101-L109  

### Description
Successful authentication returns a session token along with the user's plaintext password and API key but generates no log entry. Without logging successful logins, the application cannot detect account takeover through unusual login patterns.

### Exploitation Scenario
An attacker uses stolen credentials to log in from an unusual geographic location. Because successful logins are not logged with IP addresses or timestamps, the security team cannot detect the anomalous access pattern or alert the legitimate user.

### Remediation Guidance
Log successful authentication events:
```go
log.Printf("INFO: Successful login for user=%s (id=%d) from ip=%s", user.Username, uid, c.ClientIP())
```

### Complexity Rationale
This is rated Moderate because developers often rely on Gin's built-in access logging and overlook the need for application-level authentication event logging with security-relevant context.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand Gin handler patterns and identify that the successful authentication code path lacks structured logging.

---

## Vulnerability: No Audit Logging for Privilege Escalation Operations

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L131-L162  

### Description
The role change endpoint modifies user privileges without logging who initiated the change, what the previous and new roles are, or when the change occurred. The endpoint does not verify admin privileges, allowing any authenticated user to escalate privileges silently.

### Exploitation Scenario
A compromised low-privilege account changes its own role to `admin`. Without audit logging, the privilege escalation is invisible to the security team. The attacker uses admin access to deactivate other accounts and export sensitive data.

### Remediation Guidance
Log all privilege changes:
```go
log.Printf("WARN: Role change: userId=%d from '%s' to '%s' by callerId=%d from ip=%s",
    targetID, oldRole, body.Role, session.UserID, c.ClientIP())
```

### Complexity Rationale
This is rated Moderate because role changes are clearly security-sensitive, but the reviewer must recognize that the absence of audit logging is a distinct vulnerability from the missing authorization check.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that a role-change handler requires audit logging. This is a business logic requirement.

---

## Vulnerability: No Logging of Financial Transactions

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L195-L248  

### Description
Both the single transaction and bulk transfer handlers process financial operations without any server-side logging. Transactions are appended to an in-memory slice, but there is no persistent audit log, no logging of amounts or recipients, and no mechanism for detecting anomalous transaction patterns.

### Exploitation Scenario
An attacker with a compromised session initiates a bulk transfer of high-value transactions. The transfers complete without generating any log entries. The fraud is only discovered during manual financial reconciliation, by which time the funds are unrecoverable.

### Remediation Guidance
Log all financial transactions:
```go
log.Printf("INFO: Transaction: id=%d userId=%d amount=%.2f recipient=%s from ip=%s",
    tx.ID, session.UserID, body.Amount, body.Recipient, c.ClientIP())
```

### Complexity Rationale
This is rated Nuanced because transactions are stored in a data structure, which may give a false sense of record-keeping. A reviewer must distinguish between application data storage and security audit logging.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that transaction handlers require audit logging based on the business context of the operations.

---

## Vulnerability: No Logging of Sensitive Data Export

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L250-L285  

### Description
The data export handler allows any authenticated user to export all user records (including passwords and API keys) or all transactions without logging who requested the export. Bulk data exfiltration through this endpoint leaves no audit trail.

### Exploitation Scenario
An insider exports the complete user database including plaintext passwords via `POST /api/export/data {"type": "users"}`. No log entry records this mass data access. The insider uses the harvested credentials to compromise accounts on other services.

### Remediation Guidance
Log all data export operations:
```go
log.Printf("WARN: Data export: type=%s by userId=%d from ip=%s", body.Type, session.UserID, c.ClientIP())
```

### Complexity Rationale
This is rated Moderate because data export endpoints are recognized as high-risk operations that should be audited. The endpoint name clearly indicates bulk data access.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially identify export handlers by naming conventions and flag the absence of logging, but this requires understanding Gin handler patterns.

---

## Vulnerability: No Logging of Security Configuration Changes

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L287-L330  

### Description
The API key regeneration and MFA toggle handlers modify security-critical account settings without any logging. Regenerating an API key invalidates the previous key, and disabling MFA weakens account security. Neither operation produces any audit log entry.

### Exploitation Scenario
An attacker with a compromised session disables MFA on the admin account and regenerates the API key. The legitimate admin discovers their API key no longer works but has no log trail to determine when or how the change occurred.

### Remediation Guidance
Log all security configuration changes:
```go
log.Printf("WARN: API key regenerated: userId=%d from ip=%s", session.UserID, c.ClientIP())
log.Printf("WARN: MFA toggled: userId=%d enabled=%v from ip=%s", session.UserID, body.Enabled, c.ClientIP())
```

### Complexity Rationale
This is rated Nuanced because API key rotation and MFA management are not always recognized as security-critical operations requiring audit logging.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that MFA and API key handlers are security-sensitive operations requiring logging.
