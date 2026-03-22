# Security Companion Document: main.c

## Vulnerability: No Logging of Failed Authentication Attempts

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L131-L143  

### Description
The login handler returns HTTP 401 and 403 responses for invalid credentials and disabled accounts but does not log any failed authentication attempts. The application has no calls to `syslog()`, `fprintf(stderr, ...)`, or any other logging mechanism in the authentication flow. Without logging, brute-force attacks generate no alerts.

### Exploitation Scenario
An attacker runs automated credential stuffing against `/api/login`. Each failed attempt returns a 401 response but produces no log entry. The security team has no visibility into the attack volume, targeted usernames, or source IP addresses.

### Remediation Guidance
Add syslog or stderr logging for failed authentication:
```c
#include <syslog.h>

// On failed login:
syslog(LOG_WARNING, "Failed login attempt for user=%s", username);
```

### Complexity Rationale
This is rated Obvious because the complete absence of any logging function call (syslog, fprintf to stderr, or any logging library) in the authentication handler is immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can check for the absence of logging calls in authentication handlers and flag login functions without syslog or logging statements.

---

## Vulnerability: No Logging of Successful Authentication Events

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L135-L141  

### Description
When authentication succeeds, the handler returns a session token along with the user's plaintext password and API key in the JSON response but generates no log entry. Successful login logging is essential for detecting account takeover.

### Exploitation Scenario
An attacker who has obtained valid credentials logs in successfully. The legitimate account owner and security team have no record of the unauthorized session. The attacker maintains persistent access without detection.

### Remediation Guidance
Log successful authentication events:
```c
syslog(LOG_INFO, "Successful login for user=%s (id=%d)", u->username, u->id);
```

### Complexity Rationale
This is rated Moderate because developers often focus on logging failures rather than successes. A reviewer must understand that successful login logging is equally important for detecting unauthorized access.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the control flow of the login handler and identify that the successful authentication path lacks logging.

---

## Vulnerability: No Audit Logging for Privilege Escalation Operations

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L157-L178  

### Description
The role change handler modifies user privileges by directly overwriting the role field without logging who initiated the change, what the previous and new roles are, or when the change occurred. Any authenticated user can change any other user's role without admin verification.

### Exploitation Scenario
A compromised low-privilege account changes its own role to `admin`. Without audit logging, the privilege escalation is invisible. The attacker uses admin access to deactivate other accounts and export sensitive data.

### Remediation Guidance
Log all privilege changes:
```c
syslog(LOG_WARNING, "Role change: user_id=%d from '%s' to '%s' by caller_id=%d", target_id, target->role, new_role, uid);
```

### Complexity Rationale
This is rated Moderate because role changes are clearly security-sensitive operations, but the reviewer must recognize that the absence of audit logging is a distinct vulnerability.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that a role-change function requires audit logging. This is a business logic requirement.

---

## Vulnerability: No Logging of Financial Transactions

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L199-L228  

### Description
The transaction creation handler processes financial operations without any server-side logging. Transactions are stored in a static array, but there is no persistent audit log, no logging of amounts or recipients, and no mechanism for detecting anomalous transaction patterns.

### Exploitation Scenario
An attacker with a compromised session creates high-value transactions. The transactions complete without generating any log entries. The fraud is only discovered during manual financial reconciliation.

### Remediation Guidance
Log all financial transactions:
```c
syslog(LOG_INFO, "Transaction: id=%d user_id=%d amount=%.2f recipient=%s", tx->id, uid, tx->amount, tx->recipient);
```

### Complexity Rationale
This is rated Nuanced because transactions are stored in a static array, which may give a false sense of record-keeping. A reviewer must distinguish between application data storage and security audit logging.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that a transaction handler requires audit logging based on the business context.

---

## Vulnerability: No Logging of Sensitive Data Export

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L230-L270  

### Description
The data export handler allows any authenticated user to export all user records (including plaintext passwords and API keys) or all transactions without logging who requested the export. Mass data exfiltration through this endpoint leaves no audit trail.

### Exploitation Scenario
An insider exports the complete user database including plaintext passwords and API keys. No log entry records this bulk data access. The insider uses the harvested credentials to compromise accounts on other services.

### Remediation Guidance
Log all data export operations:
```c
syslog(LOG_WARNING, "Data export: type=%s by user_id=%d", export_type, uid);
```

### Complexity Rationale
This is rated Moderate because data export endpoints are recognized as high-risk operations that should be audited.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially identify export functions by naming conventions and flag the absence of logging.

---

## Vulnerability: No Logging of Security Configuration Changes

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L272-L318  

### Description
The API key regeneration and MFA toggle handlers modify security-critical account settings without any logging. Regenerating an API key invalidates the previous key, and disabling MFA weakens account security. Neither operation produces any audit log entry.

### Exploitation Scenario
An attacker with a compromised session disables MFA on the admin account and regenerates the API key. The legitimate admin discovers their API key no longer works but has no log trail to determine when or how the change occurred.

### Remediation Guidance
Log all security configuration changes:
```c
syslog(LOG_WARNING, "API key regenerated: user_id=%d", uid);
syslog(LOG_WARNING, "MFA toggled: user_id=%d enabled=%d", uid, enabled);
```

### Complexity Rationale
This is rated Nuanced because API key rotation and MFA management are not always recognized as security-critical operations requiring audit logging.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that MFA and API key functions are security-sensitive operations requiring logging.
