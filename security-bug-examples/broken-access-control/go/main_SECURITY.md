# Security Companion Document: main.go

## Vulnerability: Unauthenticated User Profile Access with Sensitive Data Exposure

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L101-L115  

### Description
The `getUserProfile` function returns the full `User` struct including sensitive fields (`SSN`, `Salary`) without requiring any authentication. The struct's JSON tags expose all fields directly in the response.

### Exploitation Scenario
An attacker sends `GET /api/users/1` through `GET /api/users/4` without any Authorization header. Each response returns the complete user record including Social Security numbers and salary data.

### Remediation Guidance
Require authentication and create a response struct that excludes sensitive fields:
```go
type UserResponse struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Role     string `json:"role"`
}
```

### Complexity Rationale
This is rated Obvious because the function has no authentication check at all, and the full user struct with SSN and salary is serialized directly via JSON tags.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the handler function lacks any session validation before returning sensitive data, a pattern SAST tools can identify by checking for missing authentication guards.

---

## Vulnerability: Insecure Direct Object Reference in Ticket Access with Internal Notes Exposure

**CWE:** CWE-639  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L117-L137  

### Description
The `getTicket` function authenticates the caller but does not verify that the authenticated user is the ticket assignee, creator, or has a role that permits access. Any authenticated user can access any ticket by its ID, including viewing internal notes meant only for support agents.

### Exploitation Scenario
A customer authenticated as `charlie` (customer, UserID=3) sends `GET /api/tickets/302` with their valid token. The endpoint returns the "Billing discrepancy" ticket including the `internal_notes` field containing "Stripe webhook fired twice, refund pending", which is internal operational information not meant for customers.

### Remediation Guidance
Add role-based or ownership authorization:
```go
if sess.Role == "customer" && ticket.AssigneeID != sess.UserID {
    c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
    return
}
```

### Complexity Rationale
This is rated Moderate because authentication is present, and the sensitive data is in the `internal_notes` field which is not obviously sensitive from the struct definition alone. A reviewer must understand the business context.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the authorization model to detect that the authenticated user's identity is never compared against the ticket's `AssigneeID` field.

---

## Vulnerability: Client-Controlled Role Header for Admin Authorization

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L207-L210  

### Description
The `listAllUsers` function reads the `X-User-Role` header from the client request via `c.GetHeader("X-User-Role")` to determine admin access, rather than using the `Role` field from the server-side session. Any authenticated user can set this header to "admin" to bypass the authorization check.

### Exploitation Scenario
An attacker authenticated as `charlie` (customer) sends `GET /api/admin/users` with headers `Authorization: Bearer tok_charlie` and `X-User-Role: admin`. The server reads the client-supplied header, grants admin access, and returns the complete user list including SSNs and salaries.

### Remediation Guidance
Use the server-side session role:
```go
if sess.Role != "admin" {
    c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
    return
}
```

### Complexity Rationale
This is rated Moderate because the code does perform an authorization check, but relies on a client-controlled header. A reviewer must understand that HTTP headers are attacker-controlled.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically cannot distinguish between server-side session data and client-supplied HTTP headers for authorization decisions.

---

## Vulnerability: Missing Authorization Check on Role Update Endpoint

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L222-L253  

### Description
The `updateUserRole` function allows any authenticated user to change any other user's role, including promoting themselves to admin. The function verifies authentication but performs no authorization check to ensure only administrators can modify roles.

### Exploitation Scenario
An attacker authenticated as `diana` (customer) sends `PUT /api/users/4/role` with body `{"role": "admin"}` and their valid token. The endpoint updates diana's role to "admin". The attacker can then access the admin users endpoint to retrieve all sensitive user data.

### Remediation Guidance
Restrict role updates to admin users:
```go
if sess.Role != "admin" {
    c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
    return
}
```

### Complexity Rationale
This is rated Nuanced because the endpoint has authentication, and the privilege escalation requires understanding that role modification is a sensitive operation. The code follows a standard CRUD pattern.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that role modification is a privileged operation requiring admin-only access without understanding the application's business logic.

---

## Vulnerability: Unauthenticated Debug Endpoint Exposing Secrets

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L255-L273  

### Description
The `debugConfig` function is accessible without any authentication and returns sensitive configuration data including the database connection string with credentials, session secret, and API keys for Twilio and Mailgun.

### Exploitation Scenario
An attacker sends `GET /api/debug/config` without authentication. The response contains the PostgreSQL connection string with embedded credentials, the session secret, and API keys. The attacker uses the database credentials to directly access the database or the session secret to forge session tokens.

### Remediation Guidance
Remove the debug endpoint from production code, or restrict it to authenticated admin users and strip sensitive values.

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication and directly returns hardcoded secrets and environment variables containing credentials.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the endpoint returns environment variables and hardcoded credential strings without any access control.
