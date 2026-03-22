# Security Companion Document: main.rs

## Vulnerability: Unauthenticated User Profile Access with Sensitive Data Exposure

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L47-L55  

### Description
The `get_user_profile` handler returns the full `User` struct including sensitive fields (`ssn`, `salary`) without requiring any authentication. The `#[derive(Serialize)]` on the User struct causes all fields to be serialized into the JSON response.

### Exploitation Scenario
An attacker sends `GET /api/users/1` through `GET /api/users/4` without any Authorization header. Each response returns the complete user record including Social Security numbers, salary data, and department information.

### Remediation Guidance
Require authentication and create a separate response struct that excludes sensitive fields:
```rust
#[derive(Serialize)]
struct UserResponse {
    id: u32,
    username: String,
    email: String,
    role: String,
}
```

### Complexity Rationale
This is rated Obvious because the handler has no authentication check at all, and the full user struct with SSN and salary is serialized directly via serde.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the handler function lacks any session validation before returning sensitive data, a pattern SAST tools can identify by checking for missing authentication guards.

---

## Vulnerability: Insecure Direct Object Reference in Order Access

**CWE:** CWE-639  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L57-L72  

### Description
The `get_order` handler authenticates the caller but does not verify that the authenticated user is the order's customer or has a role that permits access. Any authenticated user can access any order by its ID, including viewing other customers' shipping addresses and payment methods.

### Exploitation Scenario
A user authenticated as `diana` (customer, user_id=4) sends `GET /api/orders/401` with their valid token. The endpoint returns charlie's order including the shipping address "123 Main St" and payment method "visa-4242", exposing another customer's personal and financial information.

### Remediation Guidance
Add an ownership check after retrieving the order:
```rust
if session.role != "admin" && session.user_id != order.customer_id {
    return HttpResponse::Forbidden()
        .json(serde_json::json!({"error": "Access denied"}));
}
```

### Complexity Rationale
This is rated Moderate because authentication is present, which may give a false sense of security. A reviewer must recognize that authentication without authorization is insufficient and that the `customer_id` field is never checked.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the authorization model to detect that the authenticated user's identity is never compared against the order's `customer_id` field.

---

## Vulnerability: Client-Controlled Role Header for Admin Authorization

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L127-L134  

### Description
The `list_all_users` handler reads the `X-User-Role` header from the client request to determine admin access, rather than using the `role` field from the server-side session. Any authenticated user can set this header to "admin" to bypass the authorization check.

### Exploitation Scenario
An attacker authenticated as `charlie` (customer) sends `GET /api/admin/users` with headers `Authorization: Bearer tok_charlie` and `X-User-Role: admin`. The server reads the client-supplied header, grants admin access, and returns the complete user list including SSNs and salaries.

### Remediation Guidance
Use the server-side session role:
```rust
if session.role != "admin" {
    return HttpResponse::Forbidden()
        .json(serde_json::json!({"error": "Admin access required"}));
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
**Affected Lines:** L147-L170  

### Description
The `update_user_role` handler allows any authenticated user to change any other user's role, including promoting themselves to admin. The handler verifies authentication but performs no authorization check to ensure only administrators can modify roles.

### Exploitation Scenario
An attacker authenticated as `diana` (customer) sends `PUT /api/users/4/role` with body `{"role": "admin"}` and their valid token. The endpoint updates diana's role to "admin". The attacker can then access the admin users endpoint to retrieve all sensitive user data.

### Remediation Guidance
Restrict role updates to admin users:
```rust
if session.role != "admin" {
    return HttpResponse::Forbidden()
        .json(serde_json::json!({"error": "Admin access required"}));
}
```

### Complexity Rationale
This is rated Nuanced because the endpoint has authentication, and the privilege escalation requires understanding that role modification is a sensitive operation. Rust's type system and pattern matching may give a false sense of security.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that role modification is a privileged operation requiring admin-only access without understanding the application's business logic.

---

## Vulnerability: Unauthenticated Debug Endpoint Exposing Secrets

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L172-L185  

### Description
The `debug_config` handler is accessible without any authentication and returns sensitive configuration data including the database connection string with credentials, application secret, and API keys for Stripe and SendGrid.

### Exploitation Scenario
An attacker sends `GET /api/debug/config` without authentication. The response contains the PostgreSQL connection string with embedded credentials, the application secret, and live API keys. The attacker uses the database credentials to directly access the database or the Stripe key to make unauthorized charges.

### Remediation Guidance
Remove the debug endpoint from production code, or restrict it to authenticated admin users and strip sensitive values.

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication and directly returns hardcoded secrets and environment variables containing credentials.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the endpoint returns environment variables and hardcoded credential strings without any access control.
