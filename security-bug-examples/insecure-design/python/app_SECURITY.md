# Security Companion Document: app.py

## Vulnerability: Hardcoded Credentials in Source Code

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L11-L13  

### Description
The application stores SMTP credentials (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`) as plaintext string constants at module level. These credentials provide access to the internal mail relay and are visible to anyone with source code access. Additionally, user passwords in the `USERS` dictionary (lines 15-28) are stored in plaintext rather than being hashed, meaning a memory dump or debug endpoint exposes every user's actual password.

### Exploitation Scenario
An attacker who gains access to the source repository or a deployed artifact extracts the SMTP password `SmtpR3lay#2024!` and the mail server hostname. They connect to `mail.internal.acmecorp.io` using these credentials to send phishing emails from the legitimate corporate domain, or pivot to other internal services reachable from the mail server.

### Remediation Guidance
Load credentials from environment variables or a secrets manager:
```python
import os

SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]
```
Hash stored passwords using bcrypt or argon2 instead of storing plaintext.

### Complexity Rationale
This is rated Obvious because the credentials are plaintext string literals assigned to clearly named variables at the top of the file, immediately visible during any code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded credential patterns through simple regex matching on variable names containing "password", "pass", "credential", or "secret" assigned to string literals.

---

## Vulnerability: Verbose Error Messages Expose Internal Database Path and Stack Trace

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L187-L192  

### Description
The report generation endpoint catches database exceptions and returns the full Python traceback (`traceback.format_exc()`), the raw exception message, and the internal database file path in the JSON error response. This information disclosure reveals internal file system structure, library versions, and code paths to any authenticated user who triggers a database error.

### Exploitation Scenario
An authenticated attacker sends `POST /api/reports/generate` with `{"type": "nonexistent_table"}`. The error response includes the full stack trace showing file paths like `/app/venv/lib/python3.10/site-packages/...`, the SQLite database path `/tmp/designsvc.db`, and the exact SQL query that failed. The attacker uses this information to map the internal file system, identify library versions with known CVEs, and craft further attacks targeting the database file directly.

### Remediation Guidance
Return generic error messages to clients and log detailed errors server-side:
```python
import logging
logger = logging.getLogger(__name__)

except Exception as e:
    logger.exception("Report generation failed")
    return jsonify({"error": "Report generation failed"}), 500
```

### Complexity Rationale
This is rated Moderate because the error handling appears functional and the developer likely included details for debugging purposes. A reviewer must recognize that returning stack traces and internal paths to API clients is a security concern, not just a code quality issue.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the flow of `traceback.format_exc()` and exception details into HTTP response bodies. Tools that recognize `traceback` module usage in web response contexts can flag this.

---

## Vulnerability: Debug Endpoint Exposes User Passwords and Sensitive Fields

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Moderate  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L210-L219  

### Description
The `/api/debug/user/<id>` endpoint returns the complete user object including the plaintext password, failed attempt count, and account status. Any authenticated user can query any other user's full record, including credentials. The endpoint performs no role-based authorization check beyond basic session validation.

### Exploitation Scenario
An authenticated low-privilege user (e.g., "viewer" role) sends `GET /api/debug/user/1` and receives the admin user's complete record including `"password": "Adm1n_Pr0d!"`. The attacker now has the admin password and can log in as admin to access the configuration endpoint and all privileged operations.

### Remediation Guidance
Remove debug endpoints from production code, or restrict them to admin-only access and exclude sensitive fields:
```python
@app.route("/api/debug/user/<int:user_id>", methods=["GET"])
def debug_user(user_id):
    session = get_current_session()
    if not session:
        return jsonify({"error": "Authentication required"}), 401
    caller = USERS.get(session["user_id"])
    if not caller or caller["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user["id"], "username": user["username"],
                     "email": user["email"], "role": user["role"]})
```

### Complexity Rationale
This is rated Moderate because the endpoint name "debug" suggests it is intentional for development, but a reviewer must recognize that exposing passwords through any endpoint is a critical flaw regardless of the endpoint's stated purpose.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools cannot easily determine that the returned user object contains sensitive fields like passwords. The vulnerability depends on understanding the data model and recognizing that `jsonify(user)` serializes all fields including credentials.

---

## Vulnerability: Password Reset Token Returned in API Response with Internal Server Details

**CWE:** CWE-209  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L117-L121  

### Description
The password reset endpoint returns the reset token directly in the API response along with the internal SMTP server hostname. In a secure design, the token should only be delivered via email to the account owner. Returning it in the response allows any caller to reset any user's password without access to their email. The leaked SMTP hostname reveals internal infrastructure details.

### Exploitation Scenario
An attacker sends `POST /api/password-reset` with `{"email": "admin@acmecorp.io"}`. The response includes `{"token": "abc123...", "smtp_server": "mail.internal.acmecorp.io"}`. The attacker immediately uses the token to reset the admin password via `/api/password-reset/confirm`, taking over the admin account without ever accessing the admin's email inbox.

### Remediation Guidance
Never return reset tokens in API responses; deliver them exclusively via email:
```python
@app.route("/api/password-reset", methods=["POST"])
def request_password_reset():
    # ... generate token ...
    send_email(user["email"], f"Reset token: {reset_token}")
    return jsonify({"message": "If the email exists, a reset link has been sent"})
```

### Complexity Rationale
This is rated Nuanced because the token return might appear intentional for a development or testing workflow. Recognizing this as a design flaw requires understanding the security model of password reset flows — that the email channel is the authentication factor, and bypassing it defeats the entire mechanism.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to understand the semantic purpose of password reset tokens and that returning them in HTTP responses violates the intended security design. This is a business logic flaw rather than a code pattern issue.

---

## Vulnerability: Sensitive Configuration Exposed via Admin Endpoint

**CWE:** CWE-522  
**OWASP:** A04  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L200-L208  

### Description
The `/api/config` endpoint returns all application secrets including the database path, SMTP host, SMTP user, and SMTP password in the JSON response. While the endpoint requires admin authentication, exposing credentials through an API endpoint means they are transmitted over the network, logged in proxy/access logs, and cached in browser history. The credentials should never leave the server process.

### Exploitation Scenario
An attacker who compromises an admin session token (via XSS, session fixation, or token theft) sends `GET /api/config` and receives all infrastructure credentials. Even after the admin session expires, the attacker retains the SMTP and database credentials for persistent access to backend systems.

### Remediation Guidance
Never expose credentials through API endpoints. Return only non-sensitive operational metrics:
```python
@app.route("/api/config", methods=["GET"])
def get_config():
    # ... auth checks ...
    return jsonify({
        "session_count": len(SESSIONS),
        "user_count": len(USERS),
        "smtp_configured": bool(SMTP_HOST),
        "database_configured": bool(DATABASE_PATH),
    })
```

### Complexity Rationale
This is rated Nuanced because the endpoint is admin-restricted, which may give a false sense of security. A reviewer must understand that even admin-only endpoints should not expose raw credentials, as this creates unnecessary attack surface and violates the principle of least privilege for data exposure.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can potentially trace credential variables flowing into HTTP response bodies, but the admin-only access control may cause tools to deprioritize or skip the finding.
