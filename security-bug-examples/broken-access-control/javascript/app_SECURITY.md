# Security Companion Document: app.js

## Vulnerability: Unauthenticated User Profile Access with Sensitive Data Exposure

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L42-L49  

### Description
The `GET /api/users/:id` endpoint returns the full user object including sensitive fields (`ssn`, `salary`) without requiring any authentication. Any caller can enumerate user IDs and retrieve personally identifiable information.

### Exploitation Scenario
An attacker sends `GET /api/users/1` through `GET /api/users/4` without any Authorization header. Each response returns the complete user record including Social Security numbers and salary data, enabling identity theft or social engineering attacks.

### Remediation Guidance
Require authentication and filter sensitive fields:
```javascript
app.get("/api/users/:id", (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "Authentication required" });
  const user = users[parseInt(req.params.id, 10)];
  if (!user) return res.status(404).json({ error: "User not found" });
  const { ssn, salary, ...safeUser } = user;
  res.json(safeUser);
});
```

### Complexity Rationale
This is rated Obvious because the endpoint handler has no authentication check whatsoever, and the full user object with SSN and salary is returned directly.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the route handler lacks any session validation before returning sensitive data, a pattern SAST tools can identify by checking for missing authentication guards.

---

## Vulnerability: Insecure Direct Object Reference in Invoice Access

**CWE:** CWE-639  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L51-L63  

### Description
The `GET /api/invoices/:id` endpoint authenticates the caller but does not verify that the authenticated user owns or is authorized to view the requested invoice. Any authenticated user can access any invoice by changing the ID parameter.

### Exploitation Scenario
A user authenticated as `charlie` (employee, userId=3) sends `GET /api/invoices/1004` with their valid session token. The endpoint returns the draft invoice for "Annual compliance engagement" worth $25,000 owned by `alice`, exposing confidential financial details.

### Remediation Guidance
Add an ownership check after retrieving the invoice:
```javascript
if (invoice.owner_id !== session.userId && session.role !== "admin") {
  return res.status(403).json({ error: "Access denied" });
}
```

### Complexity Rationale
This is rated Moderate because authentication is present, which may give a false sense of security. A reviewer must recognize that authentication without authorization is insufficient.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the authorization model to detect that the authenticated user's identity is never compared against the invoice's `owner_id`.

---

## Vulnerability: Client-Controlled Role Header for Admin Authorization

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L93-L95  

### Description
The `GET /api/admin/users` endpoint reads the `x-user-role` HTTP header from the client request to determine admin access instead of using the role from the server-side session. Any authenticated user can set this header to "admin" to bypass the authorization check.

### Exploitation Scenario
An attacker authenticated as `charlie` (employee) sends `GET /api/admin/users` with headers `Authorization: Bearer sess_charlie` and `x-user-role: admin`. The server reads the client-supplied header, grants admin access, and returns the complete user list including SSNs and salaries.

### Remediation Guidance
Use the server-side session role:
```javascript
if (session.role !== "admin") {
  return res.status(403).json({ error: "Admin access required" });
}
```

### Complexity Rationale
This is rated Moderate because the code does perform an authorization check, but relies on a client-controlled header. A reviewer must understand that HTTP request headers are attacker-controlled.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically cannot distinguish between server-side session data and client-supplied HTTP headers for authorization decisions. The code structurally resembles a valid role check.

---

## Vulnerability: Missing Authorization Check on Role Update Endpoint

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L100-L114  

### Description
The `PUT /api/users/:id/role` endpoint allows any authenticated user to change any user's role, including self-promotion to admin. The endpoint verifies authentication but performs no authorization check to ensure only administrators can modify roles.

### Exploitation Scenario
An attacker authenticated as `diana` (employee) sends `PUT /api/users/4/role` with body `{"role": "admin"}`. The endpoint updates diana's role to "admin". The attacker can then access the admin users endpoint to retrieve all sensitive user data.

### Remediation Guidance
Restrict role updates to admin users:
```javascript
if (session.role !== "admin") {
  return res.status(403).json({ error: "Admin access required" });
}
```

### Complexity Rationale
This is rated Nuanced because the endpoint has authentication, and the privilege escalation requires a multi-step attack: first change your role, then leverage the elevated role to access other endpoints.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that role modification is a privileged operation requiring admin-only access without understanding the application's business logic.

---

## Vulnerability: Unauthenticated Debug Endpoint Exposing Secrets

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L116-L127  

### Description
The `/api/debug/env` endpoint is accessible without any authentication and returns sensitive configuration including the database connection string with credentials, JWT secret, payment API keys, and server runtime information.

### Exploitation Scenario
An attacker sends `GET /api/debug/env` without authentication. The response contains the MongoDB connection string with credentials, the JWT secret (enabling token forgery), and live payment API keys. The attacker uses the JWT secret to forge admin tokens or the database credentials to directly access the database.

### Remediation Guidance
Remove the debug endpoint from production code entirely, or restrict it to authenticated admin users and strip sensitive values.

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication and directly returns hardcoded secrets and environment variables containing credentials.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the endpoint returns environment variables and hardcoded credential strings without any access control, patterns that SAST tools identify through string matching and missing authentication checks.
