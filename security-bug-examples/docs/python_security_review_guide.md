# Python Security Code Review Guide

## 1. Introduction

This guide provides a structured approach to security-focused code review for Python applications. It is designed for both beginners learning to identify security vulnerabilities in Python code and experienced developers looking for a language-specific checklist to streamline their reviews.

Python's dynamic typing, rich standard library, and extensive third-party ecosystem make it a productive language — but these same qualities introduce security pitfalls that static analysis alone cannot always catch. This guide covers manual review strategies, common anti-patterns, recommended tooling, and vulnerability patterns organized by class, with cross-references to the intentionally vulnerable examples in this project.

**Audience:** Security trainees, application developers, code reviewers, and anyone evaluating Python codebases for security weaknesses.

---

## 2. Manual Review Best Practices

### 2.1 Trace Data from Entry to Sink

Python web frameworks (Flask, Django, FastAPI) accept user input through `request.args`, `request.form`, `request.get_json()`, query parameters, headers, and cookies. Trace every external input to where it is consumed — database queries, shell commands, file operations, HTTP requests, or rendered HTML. Any path from source to sink without validation or sanitization is a potential vulnerability.

### 2.2 Inspect String Formatting in Sensitive Contexts

Python offers multiple string formatting mechanisms: f-strings, `str.format()`, `%` formatting, and concatenation. When any of these are used to build SQL queries, shell commands, HTML output, or URLs with user-controlled data, treat it as a high-priority finding.

### 2.3 Review Import Statements

Scan imports for modules known to introduce risk:
- `pickle`, `shelve`, `marshal` — deserialization of untrusted data
- `os.system`, `os.popen`, `subprocess` with `shell=True` — command injection
- `eval`, `exec`, `compile` — arbitrary code execution
- `yaml.load` with `yaml.Loader` or `yaml.FullLoader` — YAML deserialization attacks
- `xml.etree.ElementTree`, `lxml.etree` with entity resolution — XXE attacks

### 2.4 Check for Hardcoded Secrets

Search for string literals that look like passwords, API keys, tokens, or connection strings. Common patterns include variables named `SECRET_KEY`, `API_KEY`, `PASSWORD`, `TOKEN`, or connection strings containing `://user:pass@host`.

### 2.5 Examine Error Handling

Look for bare `except Exception` blocks that expose stack traces, internal paths, or database details to the caller. In Flask, check for custom error handlers that return `traceback.format_exc()` or raw exception messages.

### 2.6 Evaluate Cryptographic Choices

Flag uses of `hashlib.md5()` or `hashlib.sha1()` for password hashing or integrity verification. Check for DES, ECB mode, or hardcoded encryption keys. Verify that `random` (not `secrets` or `os.urandom`) is not used for security-sensitive token generation.

### 2.7 Assess Access Control Logic

For every endpoint, verify:
- Authentication is checked before any business logic executes
- Authorization checks use server-side session data, not client-supplied headers (e.g., `X-User-Role`)
- Object-level access control prevents users from accessing resources belonging to others (IDOR)

### 2.8 Review Configuration Defaults

Check Flask `app.config` for `DEBUG = True`, permissive CORS (`Access-Control-Allow-Origin: *`), missing security headers, and verbose error responses in production code.

---

## 3. Common Security Pitfalls

### 3.1 Injection

| Anti-Pattern | Risk |
|---|---|
| `"SELECT * FROM t WHERE x = '" + user_input + "'"` | SQL injection via string concatenation |
| `"SELECT ... ORDER BY {} {}".format(col, order)` | SQL injection via unvalidated ORDER BY clause |
| `os.popen("ping -c 3 " + host)` | Command injection via `os.popen` |
| `subprocess.Popen(cmd, shell=True)` | Command injection when `cmd` includes user data |
| `os.system("tar czf /tmp/{}.tar.gz {}".format(name, path))` | Command injection via `os.system` |
| Rendering user input directly into HTML with `.format()` | Stored and reflected XSS |
| JSONP callback without sanitization | XSS via callback parameter |

### 3.2 Broken Access Control

| Anti-Pattern | Risk |
|---|---|
| Endpoint returns full user record (including SSN, salary) without field filtering | Excessive data exposure |
| Authorization check reads role from `X-User-Role` header instead of session | Client-side role spoofing |
| No ownership check on document access/update | IDOR — any authenticated user can read/modify any resource |
| Debug/config endpoints with no authentication | Information disclosure of secrets and credentials |

### 3.3 Cryptographic Failures

| Anti-Pattern | Risk |
|---|---|
| `hashlib.md5(password.encode()).hexdigest()` for password storage | Weak, unsalted password hashing |
| `DES.new(key, DES.MODE_ECB)` | Deprecated cipher in insecure mode |
| `random.seed(int(time.time()))` for token generation | Predictable PRNG seeding |
| Hardcoded `ENCRYPTION_KEY = b"s3cr3t!!"` | Key exposure in source code |

### 3.4 Insecure Design

| Anti-Pattern | Risk |
|---|---|
| Plaintext passwords stored in dictionaries | No hashing at all |
| Error responses revealing usernames, email existence, or attempt counts | User enumeration |
| Password reset tokens returned in API response body | Token leakage |
| `traceback.format_exc()` returned to client | Stack trace information disclosure |

### 3.5 Security Misconfiguration

| Anti-Pattern | Risk |
|---|---|
| `app.run(debug=True)` in production code | Debug mode exposes interactive debugger |
| `app.config["SECRET_KEY"] = "changeme"` | Weak/default secret key |
| `Access-Control-Allow-Origin` reflecting any `Origin` header | Overly permissive CORS |
| `etree.XMLParser(resolve_entities=True, no_network=False)` | XXE via XML entity resolution |
| `Server` header exposing framework and Python version | Technology fingerprinting |

### 3.6 Vulnerable Components

| Anti-Pattern | Risk |
|---|---|
| `yaml.load(payload, Loader=yaml.FullLoader)` | YAML deserialization (FullLoader still allows some unsafe constructs) |
| `Template(user_input)` with Jinja2 | Server-side template injection (SSTI) |
| Outdated package versions in `requirements.txt` | Known CVEs in dependencies |

### 3.7 Integrity Failures (Deserialization)

| Anti-Pattern | Risk |
|---|---|
| `pickle.loads(untrusted_data)` | Arbitrary code execution via pickle |
| `yaml.load(data, Loader=yaml.Loader)` | Arbitrary object instantiation via YAML |
| `exec(compile(code, ...))` with remote code | Remote code execution |
| `importlib.import_module(user_input)` | Arbitrary module loading |
| `urllib.request.urlretrieve(url, path)` without validation | Downloading and executing untrusted code |

### 3.8 Logging and Monitoring Failures

| Anti-Pattern | Risk |
|---|---|
| Login response includes `password` and `api_key` fields | Credential leakage in responses |
| No logging of failed authentication attempts | Brute-force attacks go undetected |
| No logging of privilege changes (role updates, deactivations) | Unauthorized changes are invisible |
| Bulk operations with no audit trail | Mass data exfiltration undetected |
| Data export endpoint returns raw passwords | Sensitive data in export payloads |

### 3.9 SSRF

| Anti-Pattern | Risk |
|---|---|
| `urllib.request.urlopen(user_url)` without allowlist | Unrestricted SSRF |
| Blocklist checking only `localhost` and `127.0.0.1` (missing `0.0.0.0`, `[::1]`, decimal IPs) | SSRF blocklist bypass |
| Proxy endpoint accepting arbitrary `base_url` parameter | Open proxy to internal services |
| Webhook callback URLs not validated against internal ranges | SSRF via webhook registration |

### 3.10 Race Conditions

| Anti-Pattern | Risk |
|---|---|
| Check-then-act on `self.balance` without locking | Double-spend / negative balance |
| `check_availability()` then `reserve()` without atomicity | Overselling tickets |
| Read-modify-write on shared file without file locking | Lost counter updates |
| Singleton `__new__` with `time.sleep` and no lock | Multiple singleton instances |

---

## 4. Recommended SAST Tools & Linters

### 4.1 Bandit

Bandit is a Python-specific static analysis tool that finds common security issues by examining the AST of Python source files.

**Installation:**

```bash
pip install bandit
```

**Basic usage — scan a single file:**

```bash
bandit -r injection/sql-injection/python/app.py
```

**Scan an entire directory recursively:**

```bash
bandit -r security-bug-examples/ -x tests
```

**Generate a JSON report:**

```bash
bandit -r security-bug-examples/ -f json -o bandit_report.json
```

**Filter by severity (medium and above):**

```bash
bandit -r security-bug-examples/ -ll
```

**What Bandit catches:** Use of `eval`/`exec`, `pickle.loads`, `subprocess` with `shell=True`, `os.system`, `os.popen`, hardcoded passwords, weak cryptographic functions (`md5`, `sha1`, `DES`), `yaml.load` without `SafeLoader`, binding to `0.0.0.0`, and `debug=True` in Flask.

### 4.2 Semgrep

Semgrep is a multi-language static analysis tool with pattern-based rules. It supports custom rules and has a large community rule registry.

**Installation:**

```bash
pip install semgrep
# or
brew install semgrep
```

**Scan with the default Python security ruleset:**

```bash
semgrep --config "p/python" security-bug-examples/
```

**Scan with OWASP Top 10 rules:**

```bash
semgrep --config "p/owasp-top-ten" security-bug-examples/
```

**Scan a single file:**

```bash
semgrep --config "p/python" injection/sql-injection/python/app.py
```

**Run with auto configuration (recommended for first-time scans):**

```bash
semgrep --config auto security-bug-examples/
```

**What Semgrep catches:** SQL injection patterns, command injection, XSS in Flask templates, insecure deserialization (`pickle`, `yaml`), SSRF patterns, hardcoded secrets, weak cryptography, and many framework-specific issues. Semgrep's pattern matching is particularly effective at detecting string-formatting-based injection that Bandit may miss.

---

## 5. Language-Specific Vulnerability Patterns

### 5.1 SQL Injection (CWE-89)

**Pattern: String concatenation in queries**

```python
# Vulnerable — user input concatenated directly
query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
cursor = db.execute(query)
```

**Pattern: `str.format()` in query construction**

```python
# Vulnerable — format string builds WHERE clause from user input
clauses.append("status = '{}'".format(filters["status"]))
```

**Pattern: Unvalidated ORDER BY injection**

```python
# Vulnerable — 'order' parameter (ASC/DESC) not validated
query = "SELECT * FROM products ORDER BY {} {}".format(sort_by, order)
```

**Safe alternative:**

```python
cursor = db.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{keyword}%",))
```

### 5.2 Command Injection (CWE-78)

**Pattern: `os.popen()` with string concatenation**

```python
result = os.popen("ping -c 3 " + host).read()
```

**Pattern: `subprocess.Popen` with `shell=True`**

```python
cmd = "dig {} {} +short".format(record_type, domain)
proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
```

**Pattern: `os.system()` with formatted strings**

```python
cmd = "tar czf /tmp/{}.tar.gz {}".format(sanitized_name, filepath)
os.system(cmd)
```

**Safe alternative:**

```python
# Use list form without shell=True
subprocess.run(["ping", "-c", "3", host], capture_output=True, text=True)
```

### 5.3 Cross-Site Scripting — XSS (CWE-79)

**Pattern: Stored XSS via `.format()` in HTML**

```python
# Vulnerable — post content rendered without escaping
page += "<h2>{}</h2>".format(post["title"])
page += "<div>{}</div>".format(post["content"])
```

**Pattern: Reflected XSS in search results**

```python
# Vulnerable — query reflected back into page
page += "<p>Results for: <em>{}</em></p>".format(query)
```

**Pattern: XSS via `href` attribute (javascript: protocol)**

```python
page += '<a href="{}">{}</a>'.format(user["website"], user["website"])
```

**Pattern: JSONP callback injection**

```python
response = make_response("{}({})".format(callback, data))
```

**Safe alternative:**

```python
from markupsafe import escape
page += "<h2>{}</h2>".format(escape(post["title"]))
```

### 5.4 Broken Access Control (CWE-200, CWE-284, CWE-639)

**Pattern: No authentication on sensitive endpoint**

```python
@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user_profile(user_id):
    user = USERS.get(user_id)
    return jsonify(user)  # Returns SSN, salary — no auth check
```

**Pattern: Client-controlled authorization header**

```python
role = request.headers.get("X-User-Role", "employee")
if role != "admin":
    return jsonify({"error": "Admin access required"}), 403
```

**Pattern: Missing object-level authorization**

```python
# Any authenticated user can access any document — no ownership check
doc = DOCUMENTS.get(doc_id)
return jsonify(doc)
```

### 5.5 Cryptographic Failures (CWE-327, CWE-328, CWE-330)

**Pattern: MD5 for password hashing**

```python
password_hash = hashlib.md5("admin123".encode()).hexdigest()
```

**Pattern: DES in ECB mode with hardcoded key**

```python
ENCRYPTION_KEY = b"s3cr3t!!"
cipher = DES.new(ENCRYPTION_KEY, DES.MODE_ECB)
```

**Pattern: Predictable PRNG for session tokens**

```python
random.seed(int(time.time()) + user_id)
token = "".join(random.choice(chars) for _ in range(32))
```

**Safe alternative:**

```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

import secrets
token = secrets.token_hex(32)
```

### 5.6 Insecure Design (CWE-209, CWE-522)

**Pattern: Plaintext password storage**

```python
USERS = {
    1: {"username": "admin", "password": "Adm1n_Pr0d!", ...},
}
```

**Pattern: Verbose error responses**

```python
return jsonify({
    "error": "Report generation failed",
    "details": str(e),
    "trace": traceback.format_exc(),
    "database": DATABASE_PATH,
}), 500
```

**Pattern: User enumeration via distinct error messages**

```python
return jsonify({"error": f"No account found for username '{username}'"}), 404
# vs.
return jsonify({"error": "Incorrect password", "attempts": user["failed_attempts"]}), 401
```

### 5.7 Security Misconfiguration (CWE-16, CWE-611)

**Pattern: XXE via lxml with entity resolution**

```python
parser = etree.XMLParser(resolve_entities=True, no_network=False)
tree = etree.fromstring(raw_xml, parser=parser)
```

**Pattern: Debug mode and verbose error handler**

```python
app.run(host="0.0.0.0", port=5008, debug=True)

@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({"trace": traceback.format_exc()}), 500
```

**Pattern: Overly permissive CORS**

```python
origin = request.headers.get("Origin", "*")
response.headers["Access-Control-Allow-Origin"] = origin
response.headers["Access-Control-Allow-Credentials"] = "true"
```

### 5.8 Vulnerable and Outdated Components (CWE-1104)

**Pattern: Unsafe YAML loading**

```python
parsed = yaml.load(payload, Loader=yaml.FullLoader)
```

**Pattern: Jinja2 SSTI via user-controlled template string**

```python
template_str = request.args.get("template", "{{ name }} - ${{ price }}")
tmpl = Template(template_str)
label = tmpl.render(name=product["name"], price=product["price"])
```

### 5.9 Integrity Failures — Deserialization (CWE-502, CWE-829)

**Pattern: Pickle deserialization of untrusted data**

```python
raw_bytes = base64.b64decode(data["payload"])
workflow_data = pickle.loads(raw_bytes)
```

**Pattern: Unsafe YAML deserialization**

```python
workflow_data = yaml.load(raw_bytes.decode("utf-8"), Loader=yaml.Loader)
```

**Pattern: Remote code execution via `exec`**

```python
response = urllib.request.urlopen(ext_url)
code = response.read().decode("utf-8")
exec(compile(code, f"<extension:{ext_name}>", "exec"))
```

**Pattern: Dynamic module import from user input**

```python
mod = importlib.import_module(module_name)  # module_name from request
```

### 5.10 Logging and Monitoring Failures (CWE-778)

**Pattern: Credentials in API responses**

```python
return jsonify({
    "token": token,
    "password": user["password"],
    "api_key": user["api_key"],
})
```

**Pattern: No audit logging for privilege changes**

```python
target["role"] = new_role  # Role changed with no log entry
```

### 5.11 SSRF (CWE-918)

**Pattern: Unrestricted URL fetch**

```python
url = data.get("url", "")
resp = urllib.request.urlopen(url, timeout=10)
```

**Pattern: Incomplete blocklist**

```python
blocked_hosts = ["localhost", "127.0.0.1"]
# Missing: 0.0.0.0, [::1], 169.254.x.x, decimal IP representations
```

**Pattern: Open proxy via user-supplied base URL**

```python
base_url = request.args.get("base_url", "")
full_url = base_url + path
resp = urllib.request.urlopen(full_url, timeout=10)
```

### 5.12 Race Conditions (CWE-362)

**Pattern: Check-then-act without locking**

```python
def withdraw(self, amount):
    if self.balance >= amount:
        time.sleep(0.001)
        self.balance -= amount  # Another thread may have changed balance
```

**Pattern: Read-modify-write on shared file**

```python
with open(filepath, "r") as f:
    count = int(f.read().strip())
count += 1
with open(filepath, "w") as f:
    f.write(str(count))  # Lost update if concurrent
```

**Safe alternative:**

```python
import threading
lock = threading.Lock()

def withdraw(self, amount):
    with lock:
        if self.balance >= amount:
            self.balance -= amount
```

---

## 6. Cross-References to Examples

The table below maps each vulnerability class to the Python source file and companion documentation in this project. All paths are relative to the `docs/` directory.

| Vulnerability Class | Source File | Companion Doc |
|---|---|---|
| SQL Injection (CWE-89) | [`../injection/sql-injection/python/app.py`](../injection/sql-injection/python/app.py) | [`../injection/sql-injection/python/app_SECURITY.md`](../injection/sql-injection/python/app_SECURITY.md) |
| Command Injection (CWE-78) | [`../injection/command-injection/python/app.py`](../injection/command-injection/python/app.py) | [`../injection/command-injection/python/app_SECURITY.md`](../injection/command-injection/python/app_SECURITY.md) |
| Cross-Site Scripting (CWE-79) | [`../injection/xss/python/app.py`](../injection/xss/python/app.py) | [`../injection/xss/python/app_SECURITY.md`](../injection/xss/python/app_SECURITY.md) |
| Broken Access Control (CWE-200, CWE-284, CWE-639) | [`../broken-access-control/python/app.py`](../broken-access-control/python/app.py) | [`../broken-access-control/python/app_SECURITY.md`](../broken-access-control/python/app_SECURITY.md) |
| Cryptographic Failures (CWE-327, CWE-328, CWE-330) | [`../cryptographic-failures/python/app.py`](../cryptographic-failures/python/app.py) | [`../cryptographic-failures/python/app_SECURITY.md`](../cryptographic-failures/python/app_SECURITY.md) |
| Insecure Design (CWE-209, CWE-522) | [`../insecure-design/python/app.py`](../insecure-design/python/app.py) | [`../insecure-design/python/app_SECURITY.md`](../insecure-design/python/app_SECURITY.md) |
| Security Misconfiguration (CWE-16, CWE-611) | [`../security-misconfiguration/python/app.py`](../security-misconfiguration/python/app.py) | [`../security-misconfiguration/python/app_SECURITY.md`](../security-misconfiguration/python/app_SECURITY.md) |
| Vulnerable Components (CWE-1104) | [`../vulnerable-components/python/app.py`](../vulnerable-components/python/app.py) | [`../vulnerable-components/python/app_SECURITY.md`](../vulnerable-components/python/app_SECURITY.md) |
| Auth Failures (CWE-287, CWE-307, CWE-798) | [`../auth-failures/python/app.py`](../auth-failures/python/app.py) | [`../auth-failures/python/app_SECURITY.md`](../auth-failures/python/app_SECURITY.md) |
| Integrity Failures (CWE-502, CWE-829) | [`../integrity-failures/python/app.py`](../integrity-failures/python/app.py) | [`../integrity-failures/python/app_SECURITY.md`](../integrity-failures/python/app_SECURITY.md) |
| Logging/Monitoring Failures (CWE-778) | [`../logging-monitoring-failures/python/app.py`](../logging-monitoring-failures/python/app.py) | [`../logging-monitoring-failures/python/app_SECURITY.md`](../logging-monitoring-failures/python/app_SECURITY.md) |
| SSRF (CWE-918) | [`../ssrf/python/app.py`](../ssrf/python/app.py) | [`../ssrf/python/app_SECURITY.md`](../ssrf/python/app_SECURITY.md) |
| Race Condition (CWE-362) | [`../race-condition/python/app.py`](../race-condition/python/app.py) | [`../race-condition/python/app_SECURITY.md`](../race-condition/python/app_SECURITY.md) |

---

## 7. Quick-Reference Checklist

Use this checklist during Python code reviews. Each item maps to a vulnerability class covered in this guide.

- [ ] **Input validation** — All user inputs (query params, form data, JSON bodies, headers, cookies) are validated and sanitized before use in SQL, shell commands, HTML, or URLs
- [ ] **Parameterized queries** — All SQL queries use parameterized statements (`?` placeholders), never string concatenation or formatting
- [ ] **No shell=True** — `subprocess` calls use list arguments without `shell=True`; `os.system()` and `os.popen()` are not used with user input
- [ ] **Output encoding** — All user-controlled data rendered in HTML is escaped (via `markupsafe.escape`, Jinja2 autoescaping, or equivalent)
- [ ] **Authentication on every endpoint** — All sensitive endpoints verify the session/token before processing
- [ ] **Server-side authorization** — Role and permission checks use server-side session data, not client-supplied headers
- [ ] **Object-level access control** — Resource access verifies the requesting user owns or is authorized for the specific resource
- [ ] **Strong password hashing** — Passwords are hashed with `bcrypt`, `argon2`, or `scrypt` — never `md5` or `sha1`
- [ ] **Modern encryption** — AES-GCM or AES-CBC with HMAC is used; no DES, no ECB mode
- [ ] **Cryptographic randomness** — Tokens and secrets use `secrets` module or `os.urandom()`, not `random`
- [ ] **No hardcoded secrets** — API keys, passwords, and encryption keys are loaded from environment variables or a secrets manager
- [ ] **Safe deserialization** — `pickle.loads()` is never called on untrusted data; `yaml.safe_load()` is used instead of `yaml.load()`
- [ ] **No eval/exec** — `eval()`, `exec()`, and `compile()` are not used with user-controlled input
- [ ] **SSRF protection** — Outbound HTTP requests validate URLs against an allowlist; internal/metadata IPs are blocked
- [ ] **Minimal error responses** — Error responses do not include stack traces, database paths, or internal configuration
- [ ] **No debug mode** — `app.run(debug=True)` and `app.config["DEBUG"] = True` are not present in production code
- [ ] **Secure CORS** — `Access-Control-Allow-Origin` is set to specific trusted origins, not `*` or reflected from the request
- [ ] **XXE prevention** — XML parsers disable entity resolution (`resolve_entities=False`, `no_network=True`)
- [ ] **Audit logging** — Authentication events, privilege changes, and sensitive operations are logged
- [ ] **No credentials in responses** — API responses do not include passwords, API keys, or other secrets
- [ ] **Thread safety** — Shared mutable state accessed by multiple threads uses locks or atomic operations
- [ ] **Dependency hygiene** — `requirements.txt` pins versions; dependencies are checked for known CVEs with `pip-audit` or `safety`
