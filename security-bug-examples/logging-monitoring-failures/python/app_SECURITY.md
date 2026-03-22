# Security Companion Document: app.py

## Vulnerability: No Logging of Failed Authentication Attempts

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L57-L63  

### Description
The login endpoint returns error responses for invalid credentials and disabled accounts but does not log any failed authentication attempts. Without logging, brute-force attacks, credential stuffing, and account enumeration go completely undetected. There is no call to any logging facility when authentication fails.

### Exploitation Scenario
An attacker runs a credential stuffing tool against `/api/login` with thousands of stolen username/password pairs. Every failed attempt returns a 401 response but generates no log entry. The operations team has no visibility into the attack, no ability to trigger alerts, and no forensic trail to investigate after a successful breach.

### Remediation Guidance
Log all failed authentication attempts with relevant context:
```python
import logging
logger = logging.getLogger(__name__)

# In the login handler, on failure:
logger.warning("Failed login attempt for user=%s from ip=%s", username, request.remote_addr)
```

### Complexity Rationale
This is rated Obvious because the complete absence of any logging import or logging call in the authentication handler is immediately visible during code review. Any reviewer checking for security logging would notice this gap.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can check for the absence of logging calls in authentication handlers. Rules that flag login endpoints without logging statements can catch this directly.

---

## Vulnerability: No Logging of Successful Authentication Events

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L49-L56  

### Description
When a user successfully authenticates, the endpoint returns a token but does not log the event. Successful login logging is essential for detecting account takeover (e.g., logins from unusual locations or at unusual times) and for audit trails. The response also leaks the user's password and API key, compounding the issue since there is no record of who received this sensitive data.

### Exploitation Scenario
An attacker compromises a user's credentials and logs in. Because successful logins are not logged, the legitimate user and security team have no way to detect the unauthorized session. The attacker operates under the compromised account indefinitely without triggering any alerts.

### Remediation Guidance
Log all successful authentication events:
```python
logger.info("Successful login for user=%s (id=%d) from ip=%s", user["username"], uid, request.remote_addr)
```

### Complexity Rationale
This is rated Moderate because while the absence of logging is visible, many developers focus on logging failures rather than successes. A reviewer must understand that successful login logging is equally important for detecting account compromise.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need framework-specific rules to identify that a successful authentication code path lacks logging. Simple pattern matching for missing `logger` calls requires understanding the control flow.

---

## Vulnerability: No Audit Logging for Privilege Escalation Operations

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L82-L99  

### Description
The role change endpoint (`/api/admin/users/<id>/role`) modifies user privileges without logging who made the change, what the old and new roles are, or when the change occurred. Additionally, the endpoint does not verify that the caller has admin privileges — any authenticated user can change any other user's role — but even if authorization were present, the lack of audit logging means privilege escalation events leave no trace.

### Exploitation Scenario
A compromised low-privilege account changes its own role to `admin` via the role change endpoint. Without audit logging, there is no record of the privilege escalation. The attacker then uses admin privileges to exfiltrate data, deactivate other accounts, and cover their tracks — all without generating any log entries.

### Remediation Guidance
Log all privilege changes with full context:
```python
logger.warning(
    "Role change: user_id=%d changed from '%s' to '%s' by caller_id=%d from ip=%s",
    user_id, old_role, new_role, session["user_id"], request.remote_addr
)
```

### Complexity Rationale
This is rated Moderate because the endpoint performs a clearly security-sensitive operation (role changes), but the absence of logging requires the reviewer to recognize that privilege modifications must be audited. The missing authorization check compounds the issue but is a separate vulnerability class.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools generally cannot determine that a role-change endpoint is security-sensitive and requires audit logging. This is a business logic gap that requires understanding the application's authorization model.

---

## Vulnerability: No Logging of Financial Transactions

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L117-L143  

### Description
The transaction creation endpoint and bulk transfer endpoint process financial operations without any server-side logging. While transactions are stored in an in-memory list, there is no persistent audit log, no logging of transaction amounts or recipients, and no alerting mechanism for unusual transaction patterns (e.g., high-value transfers or rapid bulk operations).

### Exploitation Scenario
An attacker with a compromised session token initiates a series of high-value bulk transfers to external accounts. Because no transaction logging exists, the fraud goes undetected until the financial reconciliation process (if one exists) discovers the discrepancy. By then, the funds are unrecoverable and there is no audit trail to determine when the fraudulent transactions occurred or from which session.

### Remediation Guidance
Log all financial transactions with full details:
```python
logger.info(
    "Transaction created: id=%d user_id=%d amount=%.2f recipient=%s from ip=%s",
    transaction["id"], session["user_id"], amount, recipient, request.remote_addr
)
```

### Complexity Rationale
This is rated Nuanced because the transactions are stored in a data structure, which may give a false sense of record-keeping. A reviewer must distinguish between application data storage and security audit logging — the in-memory list is not a durable, tamper-evident audit log.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that a transaction endpoint requires audit logging. This is a business logic requirement that depends on understanding the financial nature of the operations.

---

## Vulnerability: No Logging of Sensitive Data Export Operations

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L146-L175  

### Description
The data export endpoint allows any authenticated user to export all user records (including passwords and API keys) or all transactions without logging who requested the export or what data was accessed. The endpoint also contains a SQL injection vulnerability in the fallback path, but the complete absence of export logging means even legitimate bulk data access goes unmonitored.

### Exploitation Scenario
An insider or attacker with valid credentials exports the entire user database including plaintext passwords and API keys via `POST /api/export/data {"type": "users"}`. No log entry records this mass data exfiltration. The attacker uses the harvested credentials to compromise additional accounts across other services where users reuse passwords.

### Remediation Guidance
Log all data export operations:
```python
logger.warning(
    "Data export requested: type=%s by user_id=%d from ip=%s",
    export_type, session["user_id"], request.remote_addr
)
```

### Complexity Rationale
This is rated Moderate because data export endpoints are recognized as high-risk operations that should be logged. A reviewer familiar with data loss prevention would immediately flag the absence of logging on a bulk data export endpoint.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially identify data export endpoints by naming conventions and flag the absence of logging, but this requires framework-aware rules that understand Flask route patterns.

---

## Vulnerability: No Logging of Security Configuration Changes (MFA Toggle, API Key Regeneration)

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L178-L210  

### Description
The MFA toggle endpoint and API key regeneration endpoint modify security-critical account settings without any logging. Disabling MFA weakens account security, and regenerating an API key invalidates the old key — both are security-relevant events that should be audited. Neither operation produces any log entry recording who made the change or when.

### Exploitation Scenario
An attacker who has compromised a session token disables MFA on the admin account via `PUT /api/settings/mfa {"enabled": false}` and then regenerates the admin's API key. With no logging of these changes, the legitimate admin does not know their MFA was disabled or their API key was rotated until they attempt to use the old key or are prompted for MFA that is no longer required.

### Remediation Guidance
Log all security configuration changes:
```python
logger.warning(
    "MFA toggled: user_id=%d enabled=%s from ip=%s",
    session["user_id"], enabled, request.remote_addr
)
logger.warning(
    "API key regenerated: user_id=%d from ip=%s",
    session["user_id"], request.remote_addr
)
```

### Complexity Rationale
This is rated Nuanced because MFA and API key management endpoints are not always recognized as security-critical operations requiring audit logging. A reviewer must understand that changes to authentication factors are high-impact security events.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that MFA toggle and API key regeneration are security-sensitive operations requiring logging. These are business logic requirements that depend on understanding the security implications of each endpoint.
