# Security Companion Document: main.c

## Vulnerability: Unauthenticated User Profile Access with Sensitive Data Exposure

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L103-L114  

### Description
The `handle_get_user` function returns the full user record including sensitive fields (`ssn`, `salary`) without requiring any authentication. The function is called directly from the request router without any session validation.

### Exploitation Scenario
An attacker sends `GET /api/users/1` through `GET /api/users/4` without any Authorization header. Each response returns the complete user record including Social Security numbers and salary data for all clinic staff and patients.

### Remediation Guidance
Add authentication before returning user data and exclude sensitive fields:
```c
static enum MHD_Result handle_get_user(struct MHD_Connection *conn, int user_id) {
    const char *token = get_bearer_token(conn);
    Session *sess = find_session(token);
    if (!sess) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }
    User *user = find_user(user_id);
    if (!user) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
    }
    // Return only non-sensitive fields
    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf), "{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\",\"role\":\"%s\"}",
        user->id, user->username, user->email, user->role);
    return send_json(conn, MHD_HTTP_OK, buf);
}
```

### Complexity Rationale
This is rated Obvious because the function has no authentication check at all, and the full user struct including SSN and salary is serialized directly into the JSON response.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the handler function lacks any session validation before returning sensitive data, a pattern SAST tools can identify by checking for missing authentication guards.

---

## Vulnerability: Insecure Direct Object Reference in Medical Record Access

**CWE:** CWE-639  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L116-L133  

### Description
The `handle_get_record` function authenticates the caller but does not verify that the authenticated user is the patient whose record is being accessed, or that the user has a role (doctor/admin) that permits access to the specific record. Any authenticated user can access any medical record by its ID.

### Exploitation Scenario
A patient authenticated as `patient_b` (patient, user_id=4) sends `GET /api/records/501` with their valid token. The endpoint returns `patient_a`'s medical record containing diagnosis "Hypertension Stage 2", medication details, and doctor's notes about kidney function monitoring. This violates patient privacy and potentially HIPAA regulations.

### Remediation Guidance
Add a patient ownership or role-based authorization check:
```c
if (strcmp(sess->role, "patient") == 0 && sess->user_id != rec->patient_id) {
    return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Access denied\"}");
}
```

### Complexity Rationale
This is rated Moderate because authentication is present, which may give a false sense of security. A reviewer must recognize that authentication alone is insufficient and that the `patient_id` field is never checked against the session.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the authorization model to detect that the authenticated user's identity is never compared against the record's `patient_id` field.

---

## Vulnerability: Client-Controlled Role Header for Admin Authorization

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L141-L143  

### Description
The `handle_admin_users` function reads the `X-User-Role` HTTP header from the client request via `MHD_lookup_connection_value` to determine admin access, rather than using the `role` field from the server-side session. Any authenticated user can set this header to "admin" to bypass the authorization check.

### Exploitation Scenario
An attacker authenticated as `patient_a` sends `GET /api/admin/users` with headers `Authorization: Bearer tok_patient_a` and `X-User-Role: admin`. The server reads the client-supplied header, grants admin access, and returns the complete user list including SSNs and salaries for all clinic staff.

### Remediation Guidance
Use the server-side session role:
```c
if (strcmp(sess->role, "admin") != 0) {
    return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Admin access required\"}");
}
```

### Complexity Rationale
This is rated Moderate because the code does perform an authorization check, but relies on a client-controlled header. A reviewer must understand that HTTP headers are attacker-controlled and cannot be trusted for authorization.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically cannot distinguish between server-side session data and client-supplied HTTP headers for authorization decisions. The `MHD_lookup_connection_value` call looks like a standard header read.

---

## Vulnerability: Missing Authorization Check on Role Update Endpoint

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L193-L222  

### Description
The `handle_update_role` function allows any authenticated user to change any other user's role, including promoting themselves to admin. The function verifies authentication but performs no authorization check to ensure only administrators can modify roles.

### Exploitation Scenario
An attacker authenticated as `patient_a` sends `PUT /api/users/3/role` with body `{"role": "admin"}` and their valid token. The endpoint updates patient_a's role to "admin". The attacker can then access the admin users endpoint to retrieve all sensitive user data including SSNs and salaries.

### Remediation Guidance
Restrict role updates to admin users:
```c
if (strcmp(sess->role, "admin") != 0) {
    return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Admin access required\"}");
}
```

### Complexity Rationale
This is rated Nuanced because the endpoint has authentication, and the manual JSON parsing with `strstr` adds complexity that may distract a reviewer. The privilege escalation requires understanding that role modification is a sensitive operation.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot determine that role modification is a privileged operation requiring admin-only access without understanding the application's business logic.

---

## Vulnerability: Unauthenticated Debug Endpoint Exposing Secrets

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L224-L237  

### Description
The `handle_debug_config` function is accessible without any authentication and returns sensitive configuration data including the database connection string with credentials, application secret, and API keys for Twilio and SendGrid.

### Exploitation Scenario
An attacker sends `GET /api/debug/config` without authentication. The response contains the PostgreSQL connection string with embedded credentials (`postgres://admin:s3cret@db:5432/clinicdb`), the application secret, and API keys. The attacker uses the database credentials to directly access the clinic database containing patient records.

### Remediation Guidance
Remove the debug endpoint from production code, or restrict it to authenticated admin users and strip sensitive values.

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication and directly returns hardcoded secrets and environment variables containing credentials.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the endpoint calls `getenv()` and returns hardcoded credential strings without any access control.
