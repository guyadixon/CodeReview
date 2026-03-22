# Security Companion Document: App.java

## Vulnerability: Unauthenticated User Profile Access with Sensitive Data Exposure

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L74-L80  

### Description
The `getUserProfile` endpoint returns the full user map including sensitive fields (`ssn`, `salary`) without requiring any authentication. The method accepts a `userId` path variable and directly returns the user object from the in-memory store.

### Exploitation Scenario
An attacker sends `GET /api/users/1` through `GET /api/users/4` without any Authorization header. Each response returns the complete user record including Social Security numbers and salary data for all employees.

### Remediation Guidance
Add authentication and filter sensitive fields:
```java
@GetMapping("/api/users/{userId}")
public ResponseEntity<?> getUserProfile(@PathVariable int userId,
        @RequestHeader(value = "Authorization", required = false) String auth) {
    Map<String, Object> session = getSession(auth);
    if (session == null) {
        return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
    }
    Map<String, Object> user = USERS.get(userId);
    if (user == null) {
        return ResponseEntity.status(404).body(Map.of("error", "User not found"));
    }
    Map<String, Object> safeUser = new HashMap<>(user);
    safeUser.remove("ssn");
    safeUser.remove("salary");
    return ResponseEntity.ok(safeUser);
}
```

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication check at all, and the full user map with SSN and salary is returned directly.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the controller method lacks any session or token validation before returning sensitive data, a pattern SAST tools can identify by checking for missing authentication annotations or guards.

---

## Vulnerability: Insecure Direct Object Reference in Project Access

**CWE:** CWE-639  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L82-L95  

### Description
The `getProject` endpoint authenticates the caller but does not verify that the authenticated user is the project owner or has a role that permits access. Any authenticated user can access any project by its ID, including viewing budget details for projects they are not associated with.

### Exploitation Scenario
A developer authenticated as `charlie` (developer, userId=3) sends `GET /api/projects/201` with their valid token. The endpoint returns the "Platform Rewrite" project owned by `alice` (admin), including the $2.5M budget. Charlie can similarly access all other projects regardless of ownership.

### Remediation Guidance
Add an ownership or role-based authorization check:
```java
int ownerId = (int) project.get("ownerId");
int sessionUserId = (int) session.get("userId");
if (ownerId != sessionUserId && !"admin".equals(session.get("role"))) {
    return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
}
```

### Complexity Rationale
This is rated Moderate because authentication is present, which may give a false sense of security. A reviewer must recognize that authentication alone is insufficient and that authorization (ownership check) is missing.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the application's authorization model to detect that the authenticated user's identity is never compared against the project's `ownerId` field.

---

## Vulnerability: Client-Controlled Role Header for Admin Authorization

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L121-L127  

### Description
The `listAllUsers` endpoint reads the `X-User-Role` header from the client request to determine admin access, rather than using the role from the server-side session. The `clientRole` parameter is injected via `@RequestHeader` and compared against "admin", but this value is entirely client-controlled.

### Exploitation Scenario
An attacker authenticated as `charlie` (developer) sends `GET /api/admin/users` with headers `Authorization: Bearer key_charlie` and `X-User-Role: admin`. The server reads the client-supplied header, grants admin access, and returns the complete user list including SSNs and salaries.

### Remediation Guidance
Use the server-side session role:
```java
String sessionRole = (String) session.get("role");
if (!"admin".equals(sessionRole)) {
    return ResponseEntity.status(403).body(Map.of("error", "Admin access required"));
}
```

### Complexity Rationale
This is rated Moderate because the code does perform an authorization check, but relies on a client-controlled header injected via Spring's `@RequestHeader`. A reviewer must understand that request headers are attacker-controlled.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not distinguish between server-side session data and client-supplied HTTP headers for authorization. The `@RequestHeader` annotation makes it look like a standard Spring parameter binding.

---

## Vulnerability: Missing Authorization Check on Role Update Endpoint

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L131-L148  

### Description
The `updateUserRole` endpoint allows any authenticated user to change any other user's role, including promoting themselves or others to admin. The endpoint verifies authentication but performs no authorization check to ensure only administrators can modify roles.

### Exploitation Scenario
An attacker authenticated as `diana` (developer) sends `PUT /api/users/4/role` with body `{"role": "admin"}` and their valid token. The endpoint updates diana's role to "admin". The attacker can then access the admin users endpoint to retrieve all sensitive user data.

### Remediation Guidance
Restrict role updates to admin users:
```java
String sessionRole = (String) session.get("role");
if (!"admin".equals(sessionRole)) {
    return ResponseEntity.status(403).body(Map.of("error", "Admin access required"));
}
```

### Complexity Rationale
This is rated Nuanced because the endpoint has authentication, and the privilege escalation requires understanding that role modification is a sensitive operation. The code follows a standard CRUD pattern that may not raise immediate suspicion.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that role modification is a privileged operation requiring admin-only access without understanding the application's business logic.

---

## Vulnerability: Unauthenticated Debug Endpoint Exposing Secrets

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L150-L163  

### Description
The `/api/debug/config` endpoint is accessible without any authentication and returns sensitive configuration data including the database connection string with credentials, JWT secret, and API tokens for GitHub and Slack.

### Exploitation Scenario
An attacker sends `GET /api/debug/config` without authentication. The response contains the JDBC connection string with embedded credentials, the JWT HMAC secret (enabling token forgery), and API tokens for GitHub and Slack. The attacker uses the JWT secret to forge admin tokens or the database credentials to directly access the database.

### Remediation Guidance
Remove the debug endpoint from production code, or restrict it to authenticated admin users and strip sensitive values.

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication and directly returns hardcoded secrets and environment variables containing credentials.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the endpoint returns environment variables and hardcoded credential strings without any access control, patterns that SAST tools identify through string matching and missing authentication checks.
