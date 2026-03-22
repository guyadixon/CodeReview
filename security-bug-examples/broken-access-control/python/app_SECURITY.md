# Security Companion Document: app.py

## Vulnerability: Unauthenticated User Profile Access with Sensitive Data Exposure

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L43-L48  

### Description
The `get_user_profile` endpoint returns the full user object including sensitive fields (`ssn`, `salary`, `department`) without requiring any authentication. Any unauthenticated caller can enumerate user IDs and retrieve personally identifiable information for any user in the system.

### Exploitation Scenario
An attacker iterates through user IDs by sending `GET /api/users/1`, `GET /api/users/2`, etc. without any Authorization header. Each response returns the complete user record including Social Security numbers and salary data. The attacker harvests PII for all users in the system.

### Remediation Guidance
Require authentication and restrict the returned fields based on the caller's identity:
```python
@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user_profile(user_id):
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    safe_fields = {"id": user["id"], "username": user["username"], "email": user["email"]}
    if session["user_id"] == user_id or session["role"] == "admin":
        safe_fields["department"] = user["department"]
    return jsonify(safe_fields)
```

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication check at all, and the full user object including SSN and salary is returned directly. The absence of any access control is immediately visible.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the endpoint handler lacks any session or token validation before returning sensitive data, a pattern that SAST tools can identify by checking for missing authentication middleware or guards.

---

## Vulnerability: Insecure Direct Object Reference in Document Access

**CWE:** CWE-639  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L74-L82  

### Description
The `get_document` endpoint authenticates the caller but does not verify that the authenticated user is authorized to access the requested document. Any authenticated user can access any document by its ID, including confidential documents owned by other users, by simply changing the `doc_id` parameter.

### Exploitation Scenario
A user authenticated as `charlie` (employee, user_id=3) sends `GET /api/documents/101` with their valid token. The endpoint returns the "Q4 Financial Report" document owned by `alice` (admin), which is classified as confidential and contains sensitive financial data. The employee can similarly access document 104 containing board meeting notes about an acquisition.

### Remediation Guidance
Add an ownership or role-based authorization check after retrieving the document:
```python
@app.route("/api/documents/<int:doc_id>", methods=["GET"])
def get_document(doc_id):
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404
    if doc["owner_id"] != session["user_id"] and session["role"] != "admin":
        return jsonify({"error": "Access denied"}), 403
    return jsonify(doc)
```

### Complexity Rationale
This is rated Moderate because authentication is present, which may give a false sense of security. A reviewer must recognize that authentication alone is insufficient and that authorization (ownership check) is missing.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand the application's authorization model to detect that the authenticated user's identity is never compared against the document's `owner_id` field.

---

## Vulnerability: Client-Controlled Role Header for Admin Authorization

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L105-L107  

### Description
The `list_all_users` endpoint checks the `X-User-Role` HTTP header sent by the client to determine admin access, rather than using the role from the server-side session. Any authenticated user can set `X-User-Role: admin` in their request to bypass the authorization check and access the full user list including SSNs and salaries.

### Exploitation Scenario
An attacker authenticated as `charlie` (employee) sends `GET /api/admin/users` with headers `Authorization: Bearer token_charlie` and `X-User-Role: admin`. The server reads the client-supplied header, sees "admin", and returns the complete list of all users with their SSNs and salary information.

### Remediation Guidance
Use the server-side session role instead of a client-supplied header:
```python
@app.route("/api/admin/users", methods=["GET"])
def list_all_users():
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401
    if session["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403
    return jsonify({"users": list(USERS.values())})
```

### Complexity Rationale
This is rated Moderate because the code does perform an authorization check, but it relies on a client-controlled header rather than the server-side session. A reviewer must understand that HTTP headers are attacker-controlled and cannot be trusted for authorization decisions.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not distinguish between server-side session data and client-supplied HTTP headers for authorization purposes. The code structurally resembles a valid role check.

---

## Vulnerability: Missing Authorization Check on Role Update Endpoint

**CWE:** CWE-284  
**OWASP:** A01  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L116-L133  

### Description
The `update_user_role` endpoint allows any authenticated user to change any other user's role, including promoting themselves or others to admin. The endpoint verifies authentication but performs no authorization check to ensure only administrators can modify roles. Additionally, it updates the session role in-memory, making the privilege escalation immediately effective.

### Exploitation Scenario
An attacker authenticated as `charlie` (employee) sends `PUT /api/users/3/role` with body `{"role": "admin"}` and their valid token. The endpoint updates charlie's role to "admin" and also updates the session, granting immediate admin privileges. The attacker can then access all admin endpoints including the full user list with sensitive data.

### Remediation Guidance
Restrict role updates to admin users only:
```python
@app.route("/api/users/<int:user_id>/role", methods=["PUT"])
def update_user_role(user_id):
    session = get_current_user(request)
    if not session:
        return jsonify({"error": "Authentication required"}), 401
    if session["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403
    # ... rest of the logic
```

### Complexity Rationale
This is rated Nuanced because the endpoint does have authentication, and the session-update logic on lines 128-130 adds complexity that may distract a reviewer. The privilege escalation is a multi-step attack: first change your own role, then use the elevated role to access other endpoints.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools generally cannot determine that role modification is a privileged operation requiring admin-only access. The code follows a standard authenticated-update pattern that tools would not flag without business logic context.

---

## Vulnerability: Unauthenticated Debug Endpoint Exposing Secrets

**CWE:** CWE-200  
**OWASP:** A01  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L136-L148  

### Description
The `/api/debug/config` endpoint is accessible without any authentication and returns sensitive configuration data including the database connection string (with credentials), the application secret key, and third-party API keys for Stripe and SendGrid.

### Exploitation Scenario
An attacker sends `GET /api/debug/config` without any authentication. The response contains the database URL with embedded credentials (`postgresql://admin:s3cret@db:5432/hrdb`), the application secret key, and live API keys for payment processing (Stripe) and email services (SendGrid). The attacker uses the database credentials to directly access the database or the Stripe key to make unauthorized charges.

### Remediation Guidance
Remove the debug endpoint entirely from production code, or at minimum restrict it to admin users and strip sensitive values:
```python
@app.route("/api/debug/config", methods=["GET"])
def debug_config():
    session = get_current_user(request)
    if not session or session["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403
    config = {"debug_mode": True, "session_count": len(SESSIONS)}
    return jsonify(config)
```

### Complexity Rationale
This is rated Obvious because the endpoint has no authentication and directly returns hardcoded secrets and environment variables containing credentials. The exposure is immediately apparent.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the endpoint returns environment variables and hardcoded credential strings without any access control, patterns that SAST tools can identify through string matching and missing authentication checks.
