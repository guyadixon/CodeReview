# Security Companion Document: main.cpp

## Vulnerability: Unauthenticated User Profile Access with Sensitive Data Exposure

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L93-L102  

### Description
The `GET /api/users/:id` lambda handler returns the full user object including sensitive fields (`ssn`, `salary`) via the `user_to_json` helper without requiring any authentication. The handler is registered without any middleware or authentication guard.

### Exploitation Scenario
An attacker sends `GET /api/users/1` through `GET /api/users/4` without any Authorization header. Each response returns the complete user record including Social Security numbers and salary data for all inventory staff.

### Remediation Guidance
Add authentication before returning user data and create a safe serialization function:
```cpp
json safe_user_to_json(const User& u) {
    return json{{"id", u.id}, {"username", u.username}, {"email", u.email}, {"role", u.role}};
}
```

### Complexity Rationale
This is rated Obvious because the lambda handler has no authentication check at all, and the full user struct with SSN and salary is serialized directly via `user_to_json`.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the handler lacks any session validation before returning sensitive data, a pattern SAST tools can identify by checking for missing authentication guards.

---

## Vulnerability: Insecure Direct Object Reference in Asset Access

**CWE:** CWE-639  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L104-L119  

### Description
The `GET /api/assets/:id` handler authenticates the caller but does not verify that the authenticated user is the asset owner or has a role that permits access. Any authenticated user can access any asset by its ID, including viewing asset values and serial numbers for assets they don't own.

### Exploitation Scenario
A staff member authenticated as `diana` (staff, user_id=4) sends `GET /api/assets/601` with their valid token. The endpoint returns the "Server Rack A" asset owned by `alice` (admin), including the serial number and $45,000 value. Diana can enumerate all assets in the system.

### Remediation Guidance
Add an ownership or role-based authorization check:
```cpp
if (sess->role != "admin" && sess->user_id != it->second.owner_id) {
    res.status = 403;
    res.set_content(R"({"error":"Access denied"})", "application/json");
    return;
}
```

### Complexity Rationale
This is rated Moderate because authentication is present, which may give a false sense of security. A reviewer must recognize that authentication without authorization is insufficient.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the authorization model to detect that the authenticated user's identity is never compared against the asset's `owner_id` field.

---

## Vulnerability: Client-Controlled Role Header for Admin Authorization

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L157-L162  

### Description
The `GET /api/admin/users` handler reads the `X-User-Role` header from the client request to determine admin access, rather than using the `role` field from the server-side session. Any authenticated user can set this header to "admin" to bypass the authorization check.

### Exploitation Scenario
An attacker authenticated as `charlie` (staff) sends `GET /api/admin/users` with headers `Authorization: Bearer tok_charlie` and `X-User-Role: admin`. The server reads the client-supplied header, grants admin access, and returns the complete user list including SSNs and salaries.

### Remediation Guidance
Use the server-side session role:
```cpp
if (sess->role != "admin") {
    res.status = 403;
    res.set_content(R"({"error":"Admin access required"})", "application/json");
    return;
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
**Affected Lines:** L173-L195  

### Description
The `PUT /api/users/:id/role` handler allows any authenticated user to change any other user's role, including promoting themselves to admin. The handler verifies authentication but performs no authorization check to ensure only administrators can modify roles.

### Exploitation Scenario
An attacker authenticated as `diana` (staff) sends `PUT /api/users/4/role` with body `{"role": "admin"}` and their valid token. The endpoint updates diana's role to "admin". The attacker can then access the admin users endpoint to retrieve all sensitive user data.

### Remediation Guidance
Restrict role updates to admin users:
```cpp
if (sess->role != "admin") {
    res.status = 403;
    res.set_content(R"({"error":"Admin access required"})", "application/json");
    return;
}
```

### Complexity Rationale
This is rated Nuanced because the endpoint has authentication, and the privilege escalation requires understanding that role modification is a sensitive operation. The JSON parsing and default role logic add complexity.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that role modification is a privileged operation requiring admin-only access without understanding the application's business logic.

---

## Vulnerability: Unauthenticated Debug Endpoint Exposing Secrets and AWS Credentials

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L197-L213  

### Description
The `GET /api/debug/config` handler is accessible without any authentication and returns sensitive configuration data including the database connection string with credentials, application secret, and AWS access key and secret key.

### Exploitation Scenario
An attacker sends `GET /api/debug/config` without authentication. The response contains the PostgreSQL connection string with embedded credentials, the application secret, and AWS credentials (access key and secret key). The attacker uses the AWS credentials to access cloud resources or the database credentials to directly access the inventory database.

### Remediation Guidance
Remove the debug endpoint from production code, or restrict it to authenticated admin users and strip sensitive values.

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication and directly returns hardcoded secrets including AWS credentials and environment variables containing credentials.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the endpoint calls `std::getenv()` and returns hardcoded credential strings including AWS key patterns without any access control.
