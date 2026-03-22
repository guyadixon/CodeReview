# Security Companion Document: main.rs

## Vulnerability: No Logging of Failed Authentication Attempts

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L72-L90  

### Description
The login handler returns Unauthorized and Forbidden responses for invalid credentials and disabled accounts but does not log any failed authentication attempts. The Actix-web application has no logging crate imported or any logging calls in the authentication flow. Without logging, brute-force attacks generate no alerts.

### Exploitation Scenario
An attacker runs automated credential stuffing against `/api/login`. Each failed attempt returns a 401 response but produces no log entry. The security team has no visibility into the attack, no ability to trigger account lockout, and no forensic trail.

### Remediation Guidance
Add the `log` crate and log failed authentication:
```rust
use log::{info, warn};

// On failed login:
warn!("Failed login attempt for user={}", body.username);
```

### Complexity Rationale
This is rated Obvious because the complete absence of any logging crate import or logging macro call in the entire application is immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can check for the absence of `log` crate usage in authentication handlers and flag login endpoints without logging macros.

---

## Vulnerability: No Logging of Successful Authentication Events

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L78-L85  

### Description
When authentication succeeds, the handler returns a session token along with the user's plaintext password and API key but generates no log entry. Successful login logging is essential for detecting account takeover and building user activity baselines.

### Exploitation Scenario
An attacker who has obtained valid credentials logs in successfully. The legitimate account owner and security team have no record of the unauthorized session. The attacker maintains persistent access without detection.

### Remediation Guidance
Log successful authentication events:
```rust
info!("Successful login for user={} (id={})", user.username, uid);
```

### Complexity Rationale
This is rated Moderate because developers often focus on logging failures rather than successes. A reviewer must understand that successful login logging is equally important for detecting unauthorized access.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand Actix-web handler patterns and identify that the successful authentication code path lacks logging.

---

## Vulnerability: No Audit Logging for Privilege Escalation Operations

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L104-L124  

### Description
The role change handler modifies user privileges without logging who initiated the change, what the previous and new roles are, or when the change occurred. The handler does not verify admin privileges, allowing any authenticated user to escalate privileges silently.

### Exploitation Scenario
A compromised low-privilege account changes its own role to `admin` via the role change endpoint. Without audit logging, the privilege escalation is invisible. The attacker uses admin access to deactivate other accounts and exfiltrate data.

### Remediation Guidance
Log all privilege changes:
```rust
warn!("Role change: userId={} from '{}' to '{}' by callerId={}", target_id, old_role, body.role, session.user_id);
```

### Complexity Rationale
This is rated Moderate because role changes are clearly security-sensitive operations, but the reviewer must recognize that the absence of audit logging is a distinct vulnerability.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that a role-change handler requires audit logging. This is a business logic requirement.

---

## Vulnerability: No Logging of Financial Transactions

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L145-L198  

### Description
Both the single transaction and bulk transfer handlers process financial operations without any server-side logging. Transactions are pushed to an in-memory Vec, but there is no persistent audit log, no logging of amounts or recipients, and no mechanism for detecting anomalous transaction patterns.

### Exploitation Scenario
An attacker with a compromised session initiates a bulk transfer of high-value transactions. The transfers complete without generating any log entries. The fraud is only discovered during manual financial reconciliation.

### Remediation Guidance
Log all financial transactions:
```rust
info!("Transaction: id={} userId={} amount={:.2} recipient={}", tx.id, session.user_id, tx.amount, tx.recipient);
```

### Complexity Rationale
This is rated Nuanced because transactions are stored in a Vec, which may give a false sense of record-keeping. A reviewer must distinguish between application data storage and security audit logging.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that transaction handlers require audit logging based on the business context.

---

## Vulnerability: No Logging of Sensitive Data Export

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L210-L237  

### Description
The data export handler allows any authenticated user to export all user records (including passwords and API keys) or all transactions without logging who requested the export. Mass data exfiltration through this endpoint leaves no audit trail.

### Exploitation Scenario
An insider exports the complete user database including plaintext passwords and API keys. No log entry records this bulk data access. The insider uses the harvested credentials to compromise accounts on other services.

### Remediation Guidance
Log all data export operations:
```rust
warn!("Data export: type={} by userId={}", body.export_type, session.user_id);
```

### Complexity Rationale
This is rated Moderate because data export endpoints are recognized as high-risk operations that should be audited.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially identify export handlers by naming conventions and flag the absence of logging.

---

## Vulnerability: No Logging of Security Configuration Changes

**CWE:** CWE-778  
**OWASP:** A09  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L239-L282  

### Description
The API key regeneration and MFA toggle handlers modify security-critical account settings without any logging. Regenerating an API key invalidates the previous key, and disabling MFA weakens account security. Neither operation produces any audit log entry.

### Exploitation Scenario
An attacker with a compromised session disables MFA on the admin account and regenerates the API key. The legitimate admin discovers their API key no longer works but has no log trail to determine when or how the change occurred.

### Remediation Guidance
Log all security configuration changes:
```rust
warn!("API key regenerated: userId={}", session.user_id);
warn!("MFA toggled: userId={} enabled={}", session.user_id, body.enabled);
```

### Complexity Rationale
This is rated Nuanced because API key rotation and MFA management are not always recognized as security-critical operations requiring audit logging.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that MFA and API key handlers are security-sensitive operations requiring logging.
