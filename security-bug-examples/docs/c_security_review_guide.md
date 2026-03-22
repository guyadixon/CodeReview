# C Security Code Review Guide

## 1. Introduction

This guide provides a structured approach to security-focused code review for C applications. It is designed for both beginners learning to identify security vulnerabilities in C code and experienced developers looking for a language-specific checklist to streamline their reviews.

C's manual memory management, lack of bounds checking, direct pointer arithmetic, and minimal runtime safety make it uniquely prone to entire classes of vulnerabilities that higher-level languages prevent by design. Buffer overflows, use-after-free, null pointer dereferences, integer overflows, and format string attacks are all first-class concerns in C codebases. This guide covers manual review strategies, common anti-patterns, recommended tooling, and vulnerability patterns organized by class, with cross-references to the intentionally vulnerable examples in this project.

**Audience:** Security trainees, application developers, code reviewers, and anyone evaluating C codebases for security weaknesses.

---

## 2. Manual Review Best Practices

### 2.1 Trace Data from Entry to Sink

C programs accept external input through `argv`, `stdin` (`fgets`, `scanf`, `getline`), environment variables (`getenv`), file I/O, and network sockets. Trace every external input to where it is consumed — `system()`, `popen()`, `exec*()`, `snprintf()` into shell commands, `memcpy()`, `strcpy()`, or pointer arithmetic. Any path from source to sink without validation or bounds checking is a potential vulnerability.

### 2.2 Inspect String and Buffer Operations

C has no built-in string type — strings are null-terminated `char` arrays managed manually. When reviewing, flag:
- `strcpy()`, `strcat()`, `sprintf()` — unbounded copies with no size limit
- `strncpy()` without explicit null termination of the destination
- `snprintf()` return value ignored (truncation may produce malformed data)
- `memcpy()` where the length argument derives from untrusted input
- Stack-allocated buffers used with user-controlled sizes

### 2.3 Review Memory Lifecycle

For every `malloc()`, `calloc()`, or `realloc()` call, verify:
- The return value is checked for `NULL` before use
- Exactly one corresponding `free()` exists on every code path
- No pointer is used after its memory has been freed
- `realloc()` results are assigned to a temporary before overwriting the original pointer (to avoid leaks on failure)
- No double-free conditions exist (same pointer freed twice)

### 2.4 Check Integer Arithmetic Before Use in Allocations

When integer values are used to compute buffer sizes, array indices, or loop bounds, verify:
- Multiplication of two `int` values does not overflow before being passed to `malloc()`
- Signed-to-unsigned conversions do not produce unexpectedly large values
- User-supplied counts or sizes are validated against reasonable upper bounds
- `uint16_t` or `uint32_t` truncation does not silently discard high bits

### 2.5 Examine System Command Construction

Any use of `system()`, `popen()`, or `exec*()` with string arguments built from external input is a command injection risk. Look for:
- `snprintf(cmd, ..., "command %s", user_input)` followed by `system(cmd)`
- Sanitization that only strips a subset of dangerous characters (e.g., replacing `/` but not `;`, `|`, `&`, backticks)
- Interactive modes that pass raw user input directly to `system()`

### 2.6 Evaluate Cryptographic Choices

Flag uses of MD5 or SHA-1 for password hashing or integrity verification. Check for DES, ECB mode, hardcoded encryption keys, and use of `rand()`/`srand()` seeded with `time(NULL)` for security-sensitive token generation.

### 2.7 Assess Access Control Logic

For C programs using HTTP libraries (libmicrohttpd, libcurl), verify:
- Authentication is checked before any business logic executes
- Authorization checks use server-side session data, not client-supplied headers (e.g., `X-User-Role`)
- Object-level access control prevents users from accessing resources belonging to others (IDOR)
- Debug or diagnostic endpoints are protected or disabled in production

### 2.8 Review Thread Safety

For multi-threaded C programs using pthreads, verify:
- Shared mutable state is protected by mutexes or atomic operations
- Check-then-act sequences on shared variables are atomic
- No TOCTOU (time-of-check-to-time-of-use) gaps exist between condition checks and state modifications

---

## 3. Common Security Pitfalls

### 3.1 Command Injection

| Anti-Pattern | Risk |
|---|---|
| `snprintf(cmd, ..., "ping -c 3 %s", host); system(cmd);` | Command injection via `system()` with unsanitized input |
| `snprintf(cmd, ..., "dig %s %s +short", type, domain); system(cmd);` | Command injection in DNS lookup |
| `snprintf(cmd, ..., "tail -n %s %s \| grep '%s'", lines, path, keyword); system(cmd);` | Command injection via log search parameters |
| `snprintf(cmd, ..., "%s", user_input); system(cmd);` | Arbitrary command execution in interactive mode |
| Sanitizer that replaces `/` and `\` but not `;`, `\|`, `` ` ``, `$()` | Incomplete sanitization bypass |

### 3.2 Broken Access Control

| Anti-Pattern | Risk |
|---|---|
| Endpoint returns full user record (including SSN, salary) without authentication | Excessive data exposure |
| Authorization check reads role from `X-User-Role` header instead of session | Client-side role spoofing |
| No ownership check on record access/update — any authenticated user can read/modify any resource | IDOR |
| Debug/config endpoints with no authentication | Information disclosure of secrets and credentials |
| Role update endpoint with no admin-only check | Privilege escalation |

### 3.3 Cryptographic Failures

| Anti-Pattern | Risk |
|---|---|
| Custom `md5_simple()` for password hashing | Weak, unsalted password hashing |
| DES in ECB mode with hardcoded 8-byte key | Deprecated cipher in insecure mode |
| `srand((unsigned)time(NULL)); rand()` for session tokens | Predictable PRNG seeding |
| `static const char *SIGNING_SECRET = "..."` | Hardcoded signing key in source |
| `static const unsigned char DES_KEY[8] = {...}` | Hardcoded encryption key |

### 3.4 Memory Safety — Buffer Overflows

| Anti-Pattern | Risk |
|---|---|
| `strcpy(staging, input)` where `input` exceeds `staging` size | Stack buffer overflow |
| `values[count++] = atof(tok)` with `count < 256` but array sized to 64 | Heap/stack out-of-bounds write |
| `memcpy(dest + offset, src, len)` without checking `offset + len <= dest_size` | Out-of-bounds write |
| `uint32_t total` overflow when summing field lengths, then `malloc(total)` | Heap overflow via integer overflow in allocation size |
| `uint16_t entry_count` from untrusted data used to compute `alloc_size` | Controlled allocation size leading to out-of-bounds write |

### 3.5 Memory Safety — Use-After-Free

| Anti-Pattern | Risk |
|---|---|
| `free(ptr); ... printf("%s", ptr->field);` | Use-after-free — accessing freed memory |
| `free(original); free(original);` | Double-free — heap corruption |
| Storing pointer in notification list, then freeing the object and firing notifications | Dangling pointer callback |
| Archiving pointers to objects, freeing the objects, then reading via archived pointers | Use-after-free via stale references |

### 3.6 Memory Safety — Null Pointer Dereference

| Anti-Pattern | Risk |
|---|---|
| `Config *cfg = find_config(store, key); return cfg->value;` without NULL check | Null pointer dereference on missing key |
| `parse_line()` returns partial result (key set, value NULL), caller uses both | Null dereference on malformed input |
| `realloc()` failure sets `buffer = NULL`, then `printf("%s", buffer)` | Null dereference after allocation failure |

### 3.7 Integer Overflow

| Anti-Pattern | Risk |
|---|---|
| `int total = quantity * unit_price_cents` with large values | Signed integer overflow wrapping to negative |
| `size_t total = (size_t)(item_count * item_size)` — multiplication overflows before cast | Undersized allocation leading to heap overflow |
| `int base_cost = weight_grams * distance_km` | Overflow in shipping cost calculation |
| `long val = strtol(str, NULL, 10); return (int)val;` | Truncation from `long` to `int` |

### 3.8 Insecure Design

| Anti-Pattern | Risk |
|---|---|
| Plaintext passwords stored in structs: `char password[128]` with literal values | No hashing at all |
| Error responses revealing database credentials in error messages | Information disclosure |
| Login responses distinguishing "No account found" vs. "Incorrect password" | User enumeration |
| Password reset tokens returned in API response body | Token leakage |
| Debug endpoint exposing user passwords without admin-only restriction | Sensitive data exposure |

### 3.9 Security Misconfiguration

| Anti-Pattern | Risk |
|---|---|
| `xmlReadMemory(..., XML_PARSE_DTDLOAD \| XML_PARSE_NOENT)` | XXE via XML entity resolution |
| `static int debug_mode = 1;` in production code | Debug mode enabled by default |
| `Server` and `X-Powered-By` headers exposing library versions | Technology fingerprinting |
| `Access-Control-Allow-Origin: *` with `Allow-Credentials: true` | Overly permissive CORS |
| `static int tls_verify = 0;` | TLS certificate verification disabled |
| Diagnostics endpoint exposing database credentials | Credential leakage via misconfigured endpoint |

### 3.10 Vulnerable Components

| Anti-Pattern | Risk |
|---|---|
| Linking against outdated versions of `libcurl`, `jansson`, `libxml2` | Known CVEs in dependencies |
| No version pinning in Makefile for linked libraries | Unpredictable dependency versions |
| Using `curl_easy_setopt` without `CURLOPT_SSL_VERIFYPEER` | Potential MITM attacks |

### 3.11 Auth Failures

| Anti-Pattern | Risk |
|---|---|
| Hardcoded API key: `static const char *ADMIN_API_KEY = "..."` | Credential exposure in source |
| Hardcoded service passphrase used as authentication bypass | Backdoor authentication |
| Password reset token returned in response body | Token leakage |
| No rate limiting on login attempts | Brute-force attacks |
| `srand((unsigned)time(NULL))` for session token generation | Predictable session tokens |

### 3.12 Logging and Monitoring Failures

| Anti-Pattern | Risk |
|---|---|
| Login response includes `password` and `api_key` fields | Credential leakage in responses |
| No logging of failed authentication attempts | Brute-force attacks go undetected |
| Role changes and user deactivations with no audit trail | Unauthorized privilege changes invisible |
| Data export endpoint returns raw passwords and API keys | Sensitive data in export payloads |
| MFA toggle with no logging | Security setting changes unaudited |

### 3.13 SSRF

| Anti-Pattern | Risk |
|---|---|
| `curl_easy_setopt(curl, CURLOPT_URL, user_url)` without allowlist | Unrestricted SSRF |
| Blocklist checking only `localhost` and `127.0.0.1` (missing `0.0.0.0`, `[::1]`, decimal IPs) | SSRF blocklist bypass |
| Proxy endpoint accepting arbitrary `base_url` parameter | Open proxy to internal services |
| Webhook callback URLs not validated against internal ranges | SSRF via webhook registration |
| `CURLOPT_FOLLOWLOCATION` enabled with no redirect validation | SSRF via redirect to internal host |

### 3.14 Race Conditions

| Anti-Pattern | Risk |
|---|---|
| Read-modify-write on shared variable without mutex: `long val = shared; shared = val + 1;` | Lost updates / data corruption |
| Check-then-act on `balance` across `sched_yield()` without locking | Double-spend / negative balance |
| `if (ticket_available > 0) { sched_yield(); ticket_available--; }` | Overselling tickets |
| Singleton initialization with `if (!config_ready)` and no mutex | Multiple initializations / data race |

---

## 4. Recommended SAST Tools & Linters

### 4.1 cppcheck

cppcheck is a static analysis tool for C and C++ that detects bugs, undefined behavior, and dangerous coding patterns without requiring a build system.

**Installation:**

```bash
# Ubuntu/Debian
sudo apt-get install cppcheck

# macOS
brew install cppcheck

# From source
git clone https://github.com/danmar/cppcheck.git && cd cppcheck && make && sudo make install
```

**Basic usage — scan a single file:**

```bash
cppcheck --enable=all --inconclusive injection/command-injection/c/main.c
```

**Scan an entire directory recursively:**

```bash
cppcheck --enable=all --inconclusive -I /usr/include security-bug-examples/ 2> cppcheck_report.txt
```

**Generate XML report:**

```bash
cppcheck --enable=all --xml security-bug-examples/ 2> cppcheck_report.xml
```

**Suppress specific warnings:**

```bash
cppcheck --enable=all --suppress=missingIncludeSystem security-bug-examples/
```

**What cppcheck catches:** Buffer overflows via `strcpy`/`strcat`, null pointer dereferences, memory leaks, double-free, use-after-free, uninitialized variables, integer overflow in allocation sizes, array index out of bounds, and dangerous function usage (`gets`, `scanf` without width).

### 4.2 clang-tidy

clang-tidy is a clang-based linter that provides a rich set of checks including security-focused analyzers from the Clang Static Analyzer.

**Installation:**

```bash
# Ubuntu/Debian
sudo apt-get install clang-tidy

# macOS
brew install llvm
# clang-tidy is included with llvm
```

**Basic usage — scan a single file with security checks:**

```bash
clang-tidy -checks='clang-analyzer-*,bugprone-*,cert-*' injection/command-injection/c/main.c -- -I /usr/include
```

**Run all checks:**

```bash
clang-tidy -checks='*' memory-safety/out-of-bounds-write/c/main.c -- -std=c11
```

**Focus on security-relevant check categories:**

```bash
clang-tidy -checks='clang-analyzer-security.*,clang-analyzer-core.*,bugprone-*,cert-*' \
  -header-filter='.*' main.c -- -std=c11
```

**Export fixes as YAML:**

```bash
clang-tidy -checks='bugprone-*' -export-fixes=fixes.yaml main.c -- -std=c11
```

**What clang-tidy catches:** Null pointer dereferences (via Clang Static Analyzer path-sensitive analysis), use-after-free, double-free, buffer overflows, uninitialized reads, insecure API usage (`strcpy`, `sprintf`), CERT C coding standard violations, integer conversion issues, and suspicious `sizeof` expressions.

### 4.3 Semgrep

Semgrep is a multi-language static analysis tool with pattern-based rules. It supports custom rules and has a large community rule registry.

**Installation:**

```bash
pip install semgrep
# or
brew install semgrep
```

**Scan with the default C security ruleset:**

```bash
semgrep --config "p/c" security-bug-examples/
```

**Scan with OWASP Top 10 rules:**

```bash
semgrep --config "p/owasp-top-ten" security-bug-examples/
```

**Scan a single file:**

```bash
semgrep --config "p/c" injection/command-injection/c/main.c
```

**Run with auto configuration (recommended for first-time scans):**

```bash
semgrep --config auto security-bug-examples/
```

**What Semgrep catches:** `system()` and `popen()` calls with user-controlled arguments, `strcpy`/`sprintf` usage, format string vulnerabilities, hardcoded credentials, insecure use of `rand()`/`srand()`, missing null checks after `malloc`, and many pattern-based security issues. Semgrep's pattern matching is particularly effective at detecting command injection patterns that cppcheck may miss.

---

## 5. Language-Specific Vulnerability Patterns

### 5.1 Command Injection (CWE-78)

**Pattern: `system()` with unsanitized input**

```c
char cmd[1024];
snprintf(cmd, sizeof(cmd), "ping -c 3 %s", host);
system(cmd);
```

**Pattern: Incomplete sanitization before `system()`**

```c
char *sanitize_archive_name(const char *name) {
    static char safe_name[256];
    int j = 0;
    for (int i = 0; name[i] && j < 255; i++) {
        if (name[i] == '/' || name[i] == '\\')
            safe_name[j++] = '_';
        else
            safe_name[j++] = name[i];  // ';', '|', '`' pass through
    }
    safe_name[j] = '\0';
    return safe_name;
}
// ...
snprintf(cmd, sizeof(cmd), "tar czf /tmp/%s.tar.gz %s", safe_name, filepath);
system(cmd);
```

**Pattern: Interactive mode passing raw input to shell**

```c
fgets(input, sizeof(input), stdin);
snprintf(cmd, sizeof(cmd), "%s", input);
system(cmd);
```

**Safe alternative:**

```c
// Use execvp with argument array — no shell interpretation
char *args[] = {"ping", "-c", "3", host, NULL};
execvp(args[0], args);
```

### 5.2 Broken Access Control (CWE-200, CWE-284, CWE-639)

**Pattern: No authentication on sensitive endpoint**

```c
static enum MHD_Result handle_get_user(struct MHD_Connection *conn, int user_id) {
    User *user = find_user(user_id);
    // No auth check — returns SSN, salary to anyone
    snprintf(buf, sizeof(buf),
        "{\"id\":%d,\"ssn\":\"%s\",\"salary\":%d}", user->id, user->ssn, user->salary);
    return send_json(conn, MHD_HTTP_OK, buf);
}
```

**Pattern: Client-controlled authorization header**

```c
const char *client_role = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-User-Role");
if (!client_role || strcmp(client_role, "admin") != 0) {
    return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Admin access required\"}");
}
```

**Pattern: Missing object-level authorization**

```c
// Any authenticated user can access any record — no ownership check
MedicalRecord *rec = find_record(record_id);
snprintf(buf, sizeof(buf), "{\"diagnosis\":\"%s\"}", rec->diagnosis);
return send_json(conn, MHD_HTTP_OK, buf);
```

### 5.3 Cryptographic Failures (CWE-327, CWE-328, CWE-330)

**Pattern: MD5 for password hashing**

```c
static void md5_simple(const char *input, char *output) {
    // Custom weak hash used for password storage
    unsigned long h0 = 0x67452301;
    // ...
}
md5_simple("admin2024!", users[0].password_hash);
```

**Pattern: DES in ECB mode with hardcoded key**

```c
static const unsigned char DES_KEY[8] = {'s','3','c','r','3','t','!','!'};

static void des_ecb_xor(const unsigned char *input, unsigned char *output,
                         size_t len, const unsigned char *key, int encrypt) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % 8];  // XOR "encryption" in ECB mode
    }
}
```

**Pattern: Predictable PRNG for session tokens**

```c
srand((unsigned)time(NULL));
snprintf(sessions[i].token, sizeof(sessions[i].token),
         "%08x%08x%08x%08x",
         (unsigned)rand(), (unsigned)rand(),
         (unsigned)rand(), (unsigned)rand());
```

**Safe alternative:**

```c
#include <openssl/evp.h>
#include <openssl/rand.h>

// Use bcrypt or argon2 for password hashing
// Use RAND_bytes() for cryptographic randomness
unsigned char token[32];
RAND_bytes(token, sizeof(token));

// Use AES-GCM for encryption
```

### 5.4 Insecure Design (CWE-209, CWE-522)

**Pattern: Plaintext password storage**

```c
struct user defaults[] = {
    {1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", 1, 0},
    {2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", 1, 0},
};
```

**Pattern: Verbose error responses leaking credentials**

```c
snprintf(resp, sizeof(resp),
    "{\"error\":\"Report generation failed\","
    "\"details\":\"Could not connect to database at %s as user '%s' with password '%s'\"}",
    DB_HOST, DB_USER, DB_PASS);
```

**Pattern: User enumeration via distinct error messages**

```c
if (!u) {
    snprintf(resp, sizeof(resp),
        "{\"error\":\"No account found for username '%s'\"}", username);
    return send_json(conn, MHD_HTTP_NOT_FOUND, resp);
}
// vs.
snprintf(resp, sizeof(resp),
    "{\"error\":\"Incorrect password\",\"attempts\":%d}", u->failed_attempts);
return send_json(conn, MHD_HTTP_UNAUTHORIZED, resp);
```

**Pattern: Password reset token returned in response**

```c
snprintf(resp, sizeof(resp),
    "{\"message\":\"Password reset link sent\",\"token\":\"%s\"}", rt->token);
```

### 5.5 Security Misconfiguration (CWE-16, CWE-611)

**Pattern: XXE via libxml2 with entity resolution**

```c
xmlDocPtr doc = xmlReadMemory(body, strlen(body), "noname.xml", NULL,
                               XML_PARSE_NOERROR | XML_PARSE_DTDLOAD | XML_PARSE_NOENT);
```

**Pattern: Verbose server headers**

```c
MHD_add_response_header(resp, "Server", "libmicrohttpd/0.9.77 (Linux)");
MHD_add_response_header(resp, "X-Powered-By", "libmicrohttpd");
```

**Pattern: Overly permissive CORS**

```c
static const char *allowed_origins = "*";
MHD_add_response_header(resp, "Access-Control-Allow-Origin", allowed_origins);
MHD_add_response_header(resp, "Access-Control-Allow-Credentials", "true");
```

**Pattern: Debug mode and TLS verification disabled**

```c
static int debug_mode = 1;
static int tls_verify = 0;
```

**Safe alternative:**

```c
// Disable entity resolution in libxml2
xmlDocPtr doc = xmlReadMemory(body, strlen(body), "noname.xml", NULL,
                               XML_PARSE_NOERROR | XML_PARSE_NONET | XML_PARSE_NOENT);
// Or better: use XML_PARSE_NOENT is still risky; avoid DTD loading entirely
xmlDocPtr doc = xmlReadMemory(body, strlen(body), "noname.xml", NULL,
                               XML_PARSE_NOERROR | XML_PARSE_NONET);
```

### 5.6 Vulnerable and Outdated Components (CWE-1104)

**Pattern: Linking against outdated libraries**

```c
// Makefile references specific library versions that may have known CVEs
// -lmicrohttpd -lcurl -ljansson -lxml2
// No version pinning or vulnerability scanning
```

**Pattern: Using libcurl without SSL verification**

```c
curl_easy_setopt(curl, CURLOPT_URL, url);
curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
// Missing: CURLOPT_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYHOST
```

### 5.7 Auth Failures (CWE-287, CWE-307, CWE-798)

**Pattern: Hardcoded credentials**

```c
static const char *ADMIN_API_KEY = "aak_prod_c4d5e6f7g8h9";
static const char *SERVICE_PASSPHRASE = "svc-auth-bypass-2024";
```

**Pattern: Backdoor authentication bypass**

```c
if (strcmp(username, "service") == 0 && strcmp(password, ADMIN_API_KEY) == 0) {
    char *token = create_session(0, "service");
    // Bypasses normal authentication entirely
}
```

**Pattern: Password reset token leaked in response**

```c
snprintf(buf, sizeof(buf),
    "{\"message\":\"Reset email sent\",\"token\":\"%s\"}",
    reset_tokens[i].token);
```

**Pattern: No rate limiting on authentication**

```c
// Login handler processes every request with no throttling
// No account lockout after failed attempts
```

### 5.8 Logging and Monitoring Failures (CWE-778)

**Pattern: Credentials in API responses**

```c
snprintf(resp, sizeof(resp),
    "{\"token\":\"%s\",\"user_id\":%d,\"role\":\"%s\","
    "\"password\":\"%s\",\"api_key\":\"%s\"}",
    token, u->id, u->role, u->password, u->api_key);
```

**Pattern: No audit logging for privilege changes**

```c
strncpy(target->role, new_role, sizeof(target->role) - 1);
// Role changed with no log entry
```

**Pattern: Data export leaking passwords**

```c
snprintf(entry, sizeof(entry),
    "{\"id\":%d,\"username\":\"%s\",\"password\":\"%s\",\"api_key\":\"%s\"}",
    users[i].id, users[i].username, users[i].password, users[i].api_key);
```

### 5.9 SSRF (CWE-918)

**Pattern: Unrestricted URL fetch via libcurl**

```c
char url[512] = {0};
extract_json_string(body, "url", url, sizeof(url));
curl_easy_setopt(curl, CURLOPT_URL, url);
curl_easy_perform(curl);
```

**Pattern: Incomplete blocklist**

```c
if (strstr(target, "localhost") != NULL || strstr(target, "127.0.0.1") != NULL) {
    return send_json(conn, 403, "{\"error\":\"Blocked host\"}");
}
// Missing: 0.0.0.0, [::1], 169.254.x.x, decimal IP representations, DNS rebinding
```

**Pattern: Open proxy via user-supplied base URL**

```c
const char *base_url = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "base_url");
snprintf(full_url, sizeof(full_url), "%s%s", base_url, path);
fetch_remote(full_url, &result);
```

**Pattern: Webhook callback without internal network validation**

```c
// Only checks for http:// or https:// prefix
if (strncmp(callback_url, "http://", 7) != 0 && strncmp(callback_url, "https://", 8) != 0) {
    return send_json(conn, 400, "{\"error\":\"Only HTTP(S) callbacks supported\"}");
}
// No check for internal IPs, private ranges, or metadata endpoints
```

### 5.10 Out-of-Bounds Write (CWE-787)

**Pattern: `strcpy` into fixed-size buffer**

```c
static void import_name(Record *rec, const char *input) {
    char staging[32];
    strcpy(staging, input);  // No bounds check — overflow if input > 31 chars
    memcpy(rec->name, staging, strlen(staging) + 1);
}
```

**Pattern: Loop bound exceeds array size**

```c
double values[64];
int count = 0;
char *tok = strtok(buf, ",");
while (tok && count < 256) {  // 256 > 64 — writes past array bounds
    values[count++] = atof(tok);
    tok = strtok(NULL, ",");
}
```

**Pattern: Integer overflow in allocation size**

```c
uint32_t total = 0;
for (int i = 0; i < num_fields; i++) {
    total += strlen(fields[i]) + 1;  // uint32_t overflow with many large fields
}
char *merged = (char *)malloc(total);  // Undersized allocation
```

**Pattern: Untrusted entry count from binary data**

```c
uint16_t entry_count;
memcpy(&entry_count, data, sizeof(uint16_t));
size_t alloc_size = entry_count * sizeof(Record);  // Controlled allocation
Record *batch = (Record *)malloc(alloc_size);
// entry_count may exceed actual data, leading to reads/writes past buffer
```

### 5.11 Use-After-Free (CWE-416)

**Pattern: Accessing freed memory**

```c
task->completed = 1;
remove_task(list, i);  // Calls free(list->items[i])
printf("Post-removal: task %d label = %s\n", task->id, task->label);  // UAF
```

**Pattern: Double-free**

```c
free(original);
free(original);  // Double-free — heap corruption
```

**Pattern: Dangling pointer in callback list**

```c
notify_on_complete(list->items[0], print_task_status);
remove_task(list, 0);  // Frees the task
fire_notifications();  // Calls callback with freed pointer
```

**Pattern: Stale references after free**

```c
// Archive pointers to completed tasks
for (int i = 0; i < list->count; i++) {
    if (list->items[i]->completed)
        archived[archived_count++] = list->items[i];
}
// Free completed tasks
free(list->items[i]);
// Read via archived pointers — use-after-free
printf("[%d] %s\n", archived[i]->id, archived[i]->label);
```

### 5.12 NULL Pointer Dereference (CWE-476)

**Pattern: Missing NULL check on lookup result**

```c
static char *get_config_value(ConfigStore *store, const char *key) {
    Config *cfg = find_config(store, key);
    return cfg->value;  // Crashes if key not found (cfg == NULL)
}
```

**Pattern: Partial parse result with NULL field**

```c
ParseResult pr = parse_line(line);
// If line has no '=' or empty value, pr.value is NULL
printf("Loaded: %s = %s\n", pr.key, pr.value);  // NULL dereference
add_config(store, pr.key, pr.value);             // NULL dereference
```

**Pattern: NULL dereference after failed realloc**

```c
char *buffer = (char *)malloc(buf_size);
// ... later ...
char *new_buf = (char *)realloc(buffer, new_size);
if (!new_buf) {
    free(buffer);
    buffer = NULL;
    break;
}
buffer = new_buf;
// After loop:
printf("%s", buffer);  // buffer may be NULL if realloc failed
```

### 5.13 Integer Overflow (CWE-190)

**Pattern: Multiplication overflow in line total**

```c
static int compute_line_total(const LineItem *item) {
    return item->quantity * item->unit_price_cents;  // Overflows with large values
}
```

**Pattern: Overflow in allocation size computation**

```c
static void *allocate_buffer(int item_count, int item_size) {
    size_t total = (size_t)(item_count * item_size);  // Overflow before cast
    void *buf = malloc(total);  // Undersized allocation
}
```

**Pattern: Truncation from long to int**

```c
static int parse_quantity(const char *str) {
    long val = strtol(str, NULL, 10);
    return (int)val;  // Truncation if val > INT_MAX
}
```

**Safe alternative:**

```c
#include <stdint.h>

// Check for overflow before multiplication
if (item_count > 0 && item_size > SIZE_MAX / item_count) {
    return NULL;  // Would overflow
}
size_t total = (size_t)item_count * (size_t)item_size;
```

### 5.14 Race Conditions (CWE-362)

**Pattern: Check-then-act without locking**

```c
void *do_transfers(void *arg) {
    long bal_a = ta->alice->balance;
    sched_yield();
    ta->alice->balance = bal_a - 100;  // Another thread may have changed balance
}
```

**Pattern: Read-modify-write on shared counter**

```c
void *do_increment(void *arg) {
    long current = shared_counter;
    sched_yield();
    shared_counter = current + 1;  // Lost update
}
```

**Pattern: TOCTOU on inventory**

```c
int stock = inventory_stock;
if (stock > 0) {
    sched_yield();
    inventory_stock = stock - 1;  // Overselling
    order_count++;
}
```

**Safe alternative:**

```c
#include <pthread.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *do_transfers(void *arg) {
    pthread_mutex_lock(&lock);
    if (ta->alice->balance >= 100) {
        ta->alice->balance -= 100;
        ta->bob->balance += 100;
    }
    pthread_mutex_unlock(&lock);
}
```

---

## 6. Cross-References to Examples

The table below maps each vulnerability class to the C source file and companion documentation in this project. All paths are relative to the `docs/` directory.

| Vulnerability Class | Source File | Companion Doc |
|---|---|---|
| Command Injection (CWE-78) | [`../injection/command-injection/c/main.c`](../injection/command-injection/c/main.c) | [`../injection/command-injection/c/main_SECURITY.md`](../injection/command-injection/c/main_SECURITY.md) |
| Broken Access Control (CWE-200, CWE-284, CWE-639) | [`../broken-access-control/c/main.c`](../broken-access-control/c/main.c) | [`../broken-access-control/c/main_SECURITY.md`](../broken-access-control/c/main_SECURITY.md) |
| Cryptographic Failures (CWE-327, CWE-328, CWE-330) | [`../cryptographic-failures/c/main.c`](../cryptographic-failures/c/main.c) | [`../cryptographic-failures/c/main_SECURITY.md`](../cryptographic-failures/c/main_SECURITY.md) |
| Insecure Design (CWE-209, CWE-522) | [`../insecure-design/c/main.c`](../insecure-design/c/main.c) | [`../insecure-design/c/main_SECURITY.md`](../insecure-design/c/main_SECURITY.md) |
| Security Misconfiguration (CWE-16, CWE-611) | [`../security-misconfiguration/c/main.c`](../security-misconfiguration/c/main.c) | [`../security-misconfiguration/c/main_SECURITY.md`](../security-misconfiguration/c/main_SECURITY.md) |
| Vulnerable Components (CWE-1104) | [`../vulnerable-components/c/main.c`](../vulnerable-components/c/main.c) | [`../vulnerable-components/c/main_SECURITY.md`](../vulnerable-components/c/main_SECURITY.md) |
| Auth Failures (CWE-287, CWE-307, CWE-798) | [`../auth-failures/c/main.c`](../auth-failures/c/main.c) | [`../auth-failures/c/main_SECURITY.md`](../auth-failures/c/main_SECURITY.md) |
| Logging/Monitoring Failures (CWE-778) | [`../logging-monitoring-failures/c/main.c`](../logging-monitoring-failures/c/main.c) | [`../logging-monitoring-failures/c/main_SECURITY.md`](../logging-monitoring-failures/c/main_SECURITY.md) |
| SSRF (CWE-918) | [`../ssrf/c/main.c`](../ssrf/c/main.c) | [`../ssrf/c/main_SECURITY.md`](../ssrf/c/main_SECURITY.md) |
| Out-of-Bounds Write (CWE-787) | [`../memory-safety/out-of-bounds-write/c/main.c`](../memory-safety/out-of-bounds-write/c/main.c) | [`../memory-safety/out-of-bounds-write/c/main_SECURITY.md`](../memory-safety/out-of-bounds-write/c/main_SECURITY.md) |
| Use After Free (CWE-416) | [`../memory-safety/use-after-free/c/main.c`](../memory-safety/use-after-free/c/main.c) | [`../memory-safety/use-after-free/c/main_SECURITY.md`](../memory-safety/use-after-free/c/main_SECURITY.md) |
| NULL Pointer Dereference (CWE-476) | [`../memory-safety/null-pointer-deref/c/main.c`](../memory-safety/null-pointer-deref/c/main.c) | [`../memory-safety/null-pointer-deref/c/main_SECURITY.md`](../memory-safety/null-pointer-deref/c/main_SECURITY.md) |
| Integer Overflow (CWE-190) | [`../integer-overflow/c/main.c`](../integer-overflow/c/main.c) | [`../integer-overflow/c/main_SECURITY.md`](../integer-overflow/c/main_SECURITY.md) |
| Race Condition (CWE-362) | [`../race-condition/c/main.c`](../race-condition/c/main.c) | [`../race-condition/c/main_SECURITY.md`](../race-condition/c/main_SECURITY.md) |

---

## 7. Quick-Reference Checklist

Use this checklist during C code reviews. Each item maps to a vulnerability class covered in this guide.

- [ ] **No `system()`/`popen()` with user input** — Shell commands are constructed without user-controlled data, or `execvp()` with argument arrays is used instead
- [ ] **Bounded string operations** — `strncpy`/`snprintf` are used instead of `strcpy`/`sprintf`; destination buffers are always null-terminated
- [ ] **`memcpy` length validated** — All `memcpy`/`memmove` calls verify that the length does not exceed the destination buffer size
- [ ] **`malloc` return checked** — Every `malloc`/`calloc`/`realloc` return value is checked for `NULL` before use
- [ ] **No use-after-free** — No pointer is dereferenced after the memory it points to has been freed; pointers are set to `NULL` after `free()`
- [ ] **No double-free** — Each allocated block is freed exactly once on every code path
- [ ] **Integer overflow checks** — Multiplications used for allocation sizes or array indices are checked for overflow before use
- [ ] **Signed/unsigned conversions** — Casts between signed and unsigned types are explicit and validated; `strtol` results are range-checked before narrowing
- [ ] **Authentication on every endpoint** — All sensitive HTTP endpoints verify the session/token before processing
- [ ] **Server-side authorization** — Role and permission checks use server-side session data, not client-supplied headers
- [ ] **Object-level access control** — Resource access verifies the requesting user owns or is authorized for the specific resource
- [ ] **Strong password hashing** — Passwords are hashed with bcrypt, argon2, or scrypt — never MD5 or SHA-1
- [ ] **Modern encryption** — AES-GCM or AES-CBC with HMAC is used; no DES, no ECB mode
- [ ] **Cryptographic randomness** — Tokens and secrets use `/dev/urandom`, `RAND_bytes()`, or `getrandom()` — not `rand()`/`srand()`
- [ ] **No hardcoded secrets** — API keys, passwords, and encryption keys are loaded from environment variables or a secrets manager, not compiled into the binary
- [ ] **SSRF protection** — Outbound HTTP requests validate URLs against an allowlist; internal/metadata IPs are blocked comprehensively
- [ ] **Minimal error responses** — Error responses do not include stack traces, database credentials, or internal configuration
- [ ] **No debug mode in production** — Debug flags, verbose logging, and diagnostic endpoints are disabled or protected
- [ ] **Secure CORS** — `Access-Control-Allow-Origin` is set to specific trusted origins, not `*`
- [ ] **XXE prevention** — XML parsers disable DTD loading and entity resolution (`XML_PARSE_NONET`, no `XML_PARSE_DTDLOAD`)
- [ ] **Audit logging** — Authentication events, privilege changes, and sensitive operations are logged
- [ ] **No credentials in responses** — API responses do not include passwords, API keys, or other secrets
- [ ] **Thread safety** — Shared mutable state accessed by multiple threads uses `pthread_mutex_t` or atomic operations
- [ ] **Dependency hygiene** — Linked libraries are version-pinned; dependencies are checked for known CVEs
