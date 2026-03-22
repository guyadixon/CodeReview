# C++ Security Code Review Guide

## 1. Introduction

This guide provides a structured approach to security-focused code review for C++ applications. It is designed for both beginners learning to identify security vulnerabilities in C++ code and experienced developers looking for a language-specific checklist to streamline their reviews.

C++ inherits many of C's low-level risks — manual memory management, pointer arithmetic, and the absence of bounds checking — while adding its own layer of complexity through classes, templates, smart pointers, the STL, RAII, and operator overloading. When used correctly, C++ features like `std::unique_ptr`, `std::vector`, and RAII can eliminate entire vulnerability classes. When misused, they create subtle bugs that are harder to spot than their C equivalents: dangling references from moved-from objects, use-after-free through raw pointer aliases to smart-pointer-managed memory, iterator invalidation, and implicit conversions in template code. This guide covers manual review strategies, common anti-patterns, recommended tooling, and vulnerability patterns organized by class, with cross-references to the intentionally vulnerable examples in this project.

**Audience:** Security trainees, application developers, code reviewers, and anyone evaluating C++ codebases for security weaknesses.

---

## 2. Manual Review Best Practices

### 2.1 Trace Data from Entry to Sink

C++ programs accept external input through `argv`, `std::cin`, `std::getline`, file streams (`std::ifstream`), network sockets, and HTTP library request objects (e.g., `httplib::Request`). Trace every external input to where it is consumed — `system()`, `popen()`, `std::string` concatenation into shell commands, `std::memcpy()`, `std::strcpy()`, or pointer arithmetic. Any path from source to sink without validation or bounds checking is a potential vulnerability.

### 2.2 Inspect String and Buffer Operations

C++ offers both C-style `char*` buffers and `std::string`. Both can be misused:
- `std::strcpy()`, `std::strcat()`, `std::sprintf()` — unbounded copies inherited from C
- `std::strncpy()` without explicit null termination of the destination
- `std::snprintf()` return value ignored (truncation may produce malformed data)
- `std::memcpy()` where the length argument derives from untrusted input
- Mixing `std::string` with raw `char*` buffers — `.c_str()` lifetime issues, implicit conversions
- `std::string::substr()` with unchecked indices

### 2.3 Review Memory Lifecycle and Ownership

C++ adds smart pointers and RAII on top of C's manual memory model. For every allocation, verify:
- Raw `new`/`delete` pairs are balanced — prefer `std::unique_ptr` or `std::shared_ptr`
- No raw pointer aliases exist to smart-pointer-managed memory that outlive the smart pointer
- `std::unique_ptr` is not `.get()`-ed and stored in a raw pointer that survives a move or reset
- `std::shared_ptr` cycles are broken with `std::weak_ptr`
- `delete[]` is used for `new[]` allocations (not `delete`)
- `std::free()` is used for `std::malloc()` allocations, `delete` for `new`
- No pointer is used after the object it points to has been freed or moved from
- `std::realloc()` results are assigned to a temporary before overwriting the original pointer

### 2.4 Check Integer Arithmetic Before Use in Allocations

When integer values are used to compute buffer sizes, array indices, or loop bounds, verify:
- Multiplication of two `int` values does not overflow before being passed to `new[]` or `malloc()`
- `static_cast<size_t>(a * b)` — the multiplication may overflow before the cast
- Signed-to-unsigned conversions do not produce unexpectedly large values
- User-supplied counts or sizes are validated against reasonable upper bounds
- `int16_t` or `uint16_t` truncation does not silently discard high bits
- Template type deduction does not silently widen or narrow integer types

### 2.5 Examine System Command Construction

Any use of `system()`, `popen()`, or `exec*()` with string arguments built from external input is a command injection risk. Look for:
- `std::string cmd = "command " + user_input;` followed by `system(cmd.c_str())`
- `popen(cmd.c_str(), "r")` where `cmd` includes user-controlled data
- Sanitization that only strips a subset of dangerous characters (e.g., replacing `/` but not `;`, `|`, `&`, backticks)
- Interactive modes that pass raw `std::getline` input directly to `system()` or `popen()`

### 2.6 Evaluate Cryptographic Choices

Flag uses of MD5 or SHA-1 for password hashing or integrity verification. Check for DES, ECB mode, hardcoded encryption keys, and use of `rand()`/`srand()` seeded with `time(nullptr)` for security-sensitive token generation. In C++, also watch for custom hash functions built on `std::hash<>` being used as cryptographic primitives — `std::hash` is not a cryptographic hash.

### 2.7 Assess Access Control Logic

For C++ programs using HTTP libraries (cpp-httplib, Crow, Boost.Beast), verify:
- Authentication is checked before any business logic executes
- Authorization checks use server-side session data, not client-supplied headers (e.g., `X-User-Role`)
- Object-level access control prevents users from accessing resources belonging to others (IDOR)
- Debug or diagnostic endpoints are protected or disabled in production

### 2.8 Review Thread Safety

For multi-threaded C++ programs using `std::thread`, verify:
- Shared mutable state is protected by `std::mutex` or `std::atomic` operations
- Check-then-act sequences on shared variables are atomic
- No TOCTOU (time-of-check-to-time-of-use) gaps exist between condition checks and state modifications
- `std::this_thread::yield()` between a read and a write on shared data is a strong indicator of a race condition
- Lazy-initialized singletons use `std::call_once` or C++11 static local initialization, not manual `if (instance == nullptr)` checks

### 2.9 Watch for C++ Specific Pitfalls

- **Iterator invalidation:** Modifying a container (insert, erase, push_back) while iterating over it
- **Dangling references from temporaries:** Returning a reference to a local variable or a temporary
- **Implicit conversions:** Constructors without `explicit`, narrowing conversions in initializer lists
- **Exception safety:** Resources acquired before an exception is thrown must be released (prefer RAII)
- **Object slicing:** Passing a derived class by value to a function expecting a base class

---

## 3. Common Security Pitfalls

### 3.1 Command Injection

| Anti-Pattern | Risk |
|---|---|
| `std::string cmd = "ping -c 3 " + host; system(cmd.c_str());` | Command injection via `system()` with unsanitized input |
| `popen(cmd.c_str(), "r")` where `cmd` includes user data | Command injection via `popen()` |
| `std::string cmd = "dig " + type + " " + domain + " +short"; popen(cmd.c_str(), "r");` | Command injection in DNS lookup |
| `std::string cmd = "tail -n " + lines + " " + path + " \| grep '" + keyword + "'"; popen(cmd.c_str(), "r");` | Command injection via log search parameters |
| `std::getline(std::cin, input); popen(input.c_str(), "r");` | Arbitrary command execution in interactive mode |
| Sanitizer that replaces `/` and `\\` but not `;`, `\|`, `` ` ``, `$()` | Incomplete sanitization bypass |

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
| Custom `md5_hash()` using `std::hash<>` for password storage | Weak, non-cryptographic password hashing |
| DES-like XOR "encryption" with hardcoded 8-byte key | Deprecated cipher in insecure mode |
| `srand(static_cast<unsigned>(time(nullptr))); rand()` for session tokens | Predictable PRNG seeding |
| `static const std::string SIGNING_SECRET = "..."` | Hardcoded signing key in source |
| `static const unsigned char DES_KEY[8] = {...}` | Hardcoded encryption key |
| `sha1_hash()` for password hashing | Weak hash algorithm for credentials |

### 3.4 Memory Safety — Buffer Overflows

| Anti-Pattern | Risk |
|---|---|
| `std::strcpy(entry.label, input)` where `input` exceeds `label` size | Stack buffer overflow via C-style string copy in C++ struct |
| `buffer_[size_ + i] = data[i]` without checking `size_ + count <= capacity_` | Heap out-of-bounds write in class method |
| `readings[count++]` with no upper bound check on `count` vs array size | Stack out-of-bounds write |
| `std::memcpy(dest, temp, needed)` without checking `needed <= dest_size` | Out-of-bounds write via unchecked memcpy |
| `uint32_t total = num_entries * line_size` — overflow before allocation | Undersized allocation leading to heap overflow |

### 3.5 Memory Safety — Use-After-Free

| Anti-Pattern | Risk |
|---|---|
| `store.remove(index); std::cout << ref->title;` — accessing freed object via stale pointer | Use-after-free via dangling raw pointer |
| `store.remove(1); bus.publish();` — event bus holds pointer to freed object | Dangling pointer in callback/listener list |
| `snapshot->content = doc->content; store.remove(index);` — shallow copy shares freed buffer | Use-after-free via shallow copy of internal pointer |
| `store.remove(0); std::free(content_ptr);` — double-free of content buffer | Double-free — heap corruption |
| `std::free(buf); std::cout << old_buf;` — using stale pointer after realloc failure | Use-after-free after failed realloc |

### 3.6 Memory Safety — Null Pointer Dereference

| Anti-Pattern | Risk |
|---|---|
| `SensorReading *r = registry.get_latest(id); double val = r->value;` without NULL check | Null pointer dereference on missing sensor |
| `SensorReading *parsed = parse_reading(line); registry.record(parsed->sensor_id, ...);` without NULL check | Null dereference on malformed input |
| `SensorReading *r1 = registry.get_latest(id1); double diff = r1->value - r2->value;` | Null dereference when comparing non-existent sensors |
| `compute_average()` with division by zero when `count == 0` | Division by zero (related null-safety issue) |

### 3.7 Integer Overflow

| Anti-Pattern | Risk |
|---|---|
| `int total = quantity * unit_price_cents` with large values | Signed integer overflow wrapping to negative |
| `static_cast<size_t>(record_count * record_size)` — multiplication overflows before cast | Undersized allocation leading to heap overflow |
| `int interest = current * rate_bp / 10000` — intermediate overflow | Incorrect compound interest calculation |
| `int16_t hash = hash * 31 + static_cast<int16_t>(c)` | Narrow-type overflow in hash computation |
| `int scaled = amount * numerator / denominator` | Intermediate overflow in scaling operation |

### 3.8 Insecure Design

| Anti-Pattern | Risk |
|---|---|
| Plaintext passwords stored in structs or `std::unordered_map` | No hashing at all |
| Error responses revealing database credentials in error messages | Information disclosure |
| Login responses distinguishing "No account found" vs. "Incorrect password" | User enumeration |
| Password reset tokens returned in API response body | Token leakage |
| Debug endpoint exposing user passwords without admin-only restriction | Sensitive data exposure |
| `traceback`-style error details returned to client | Stack trace information disclosure |

### 3.9 Security Misconfiguration

| Anti-Pattern | Risk |
|---|---|
| XML parsing with entity resolution enabled (libxml2 flags) | XXE via XML entity resolution |
| `static int debug_mode = 1;` or `static bool debug = true;` in production code | Debug mode enabled by default |
| `Server` and `X-Powered-By` headers exposing library versions | Technology fingerprinting |
| `Access-Control-Allow-Origin: *` with `Allow-Credentials: true` | Overly permissive CORS |
| TLS certificate verification disabled in HTTP client | MITM attacks |
| Diagnostics endpoint exposing database credentials | Credential leakage via misconfigured endpoint |

### 3.10 Vulnerable Components

| Anti-Pattern | Risk |
|---|---|
| Linking against outdated versions of `cpp-httplib`, `nlohmann/json`, `libxml2` | Known CVEs in dependencies |
| No version pinning in Makefile or CMakeLists.txt for linked libraries | Unpredictable dependency versions |
| Header-only libraries vendored without version tracking | Stale dependencies with known vulnerabilities |
| Using HTTP client without SSL verification | Potential MITM attacks |

### 3.11 Auth Failures

| Anti-Pattern | Risk |
|---|---|
| Hardcoded API key: `static const std::string ADMIN_API_KEY = "..."` | Credential exposure in source |
| Hardcoded service passphrase used as authentication bypass | Backdoor authentication |
| Password reset token returned in response body | Token leakage |
| No rate limiting on login attempts | Brute-force attacks |
| `srand(static_cast<unsigned>(time(nullptr)))` for session token generation | Predictable session tokens |

### 3.12 Logging and Monitoring Failures

| Anti-Pattern | Risk |
|---|---|
| Login response includes `password` and `api_key` fields in JSON | Credential leakage in responses |
| No logging of failed authentication attempts | Brute-force attacks go undetected |
| Role changes and user deactivations with no audit trail | Unauthorized privilege changes invisible |
| Data export endpoint returns raw passwords and API keys | Sensitive data in export payloads |
| MFA toggle with no logging | Security setting changes unaudited |

### 3.13 SSRF

| Anti-Pattern | Risk |
|---|---|
| `httplib::Client cli(host, port); cli.Get(path);` with user-controlled host | Unrestricted SSRF |
| Blocklist checking only `localhost` and `127.0.0.1` (missing `0.0.0.0`, `[::1]`, decimal IPs) | SSRF blocklist bypass |
| Proxy endpoint accepting arbitrary `base_url` parameter | Open proxy to internal services |
| Webhook callback URLs validated only for `http://`/`https://` prefix | SSRF via webhook registration to internal hosts |
| `config_url` import with partial metadata IP check (`169.254` only) | Incomplete SSRF protection |

### 3.14 Race Conditions

| Anti-Pattern | Risk |
|---|---|
| `long current = balance; std::this_thread::yield(); balance = current - amount;` | Double-spend / negative balance |
| `if (available > 0) { std::this_thread::yield(); available--; }` | Overselling tickets |
| `long current = value; std::this_thread::yield(); value = current + 1;` | Lost counter updates |
| `if (instance == nullptr) { std::this_thread::yield(); instance = new Config(); }` | Multiple singleton instances / data race |
| Read-modify-write on `std::map` values without mutex | Lost inventory updates |

---

## 4. Recommended SAST Tools & Linters

### 4.1 cppcheck

cppcheck is a static analysis tool for C and C++ that detects bugs, undefined behavior, and dangerous coding patterns without requiring a build system. It understands C++ constructs including classes, templates, and STL containers.

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
cppcheck --enable=all --inconclusive --std=c++17 injection/command-injection/cpp/main.cpp
```

**Scan an entire directory recursively:**

```bash
cppcheck --enable=all --inconclusive --std=c++17 -I /usr/include security-bug-examples/ 2> cppcheck_report.txt
```

**Generate XML report:**

```bash
cppcheck --enable=all --std=c++17 --xml security-bug-examples/ 2> cppcheck_report.xml
```

**Suppress specific warnings:**

```bash
cppcheck --enable=all --suppress=missingIncludeSystem --std=c++17 security-bug-examples/
```

**What cppcheck catches:** Buffer overflows via `strcpy`/`strcat`, null pointer dereferences, memory leaks (including `new`/`delete` mismatches), double-free, use-after-free, uninitialized variables, integer overflow in allocation sizes, array index out of bounds, dangerous function usage (`gets`, `scanf` without width), STL container misuse, and iterator invalidation.

### 4.2 clang-tidy

clang-tidy is a clang-based linter that provides a rich set of checks including security-focused analyzers from the Clang Static Analyzer. It has excellent C++ support including template analysis and modern C++ idiom checks.

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
clang-tidy -checks='clang-analyzer-*,bugprone-*,cert-*,cppcoreguidelines-*' \
  injection/command-injection/cpp/main.cpp -- -std=c++17 -I /usr/include
```

**Run all checks:**

```bash
clang-tidy -checks='*' memory-safety/out-of-bounds-write/cpp/main.cpp -- -std=c++17
```

**Focus on security-relevant check categories:**

```bash
clang-tidy -checks='clang-analyzer-security.*,clang-analyzer-core.*,bugprone-*,cert-*,cppcoreguidelines-owning-memory,cppcoreguidelines-no-malloc' \
  -header-filter='.*' main.cpp -- -std=c++17
```

**Export fixes as YAML:**

```bash
clang-tidy -checks='bugprone-*,modernize-*' -export-fixes=fixes.yaml main.cpp -- -std=c++17
```

**What clang-tidy catches:** Null pointer dereferences (via path-sensitive analysis), use-after-free, double-free, buffer overflows, uninitialized reads, insecure API usage (`strcpy`, `sprintf`), CERT C++ coding standard violations, integer conversion issues, suspicious `sizeof` expressions, use of `new`/`delete` instead of smart pointers (`cppcoreguidelines-owning-memory`), use of `malloc`/`free` in C++ code (`cppcoreguidelines-no-malloc`), and modernization suggestions (e.g., `auto`, range-based for, `make_unique`).

### 4.3 Semgrep

Semgrep is a multi-language static analysis tool with pattern-based rules. It supports custom rules and has a large community rule registry.

**Installation:**

```bash
pip install semgrep
# or
brew install semgrep
```

**Scan with the default C++ security ruleset:**

```bash
semgrep --config "p/cpp" security-bug-examples/
```

**Scan with OWASP Top 10 rules:**

```bash
semgrep --config "p/owasp-top-ten" security-bug-examples/
```

**Scan a single file:**

```bash
semgrep --config "p/cpp" injection/command-injection/cpp/main.cpp
```

**Run with auto configuration (recommended for first-time scans):**

```bash
semgrep --config auto security-bug-examples/
```

**What Semgrep catches:** `system()` and `popen()` calls with user-controlled arguments, `strcpy`/`sprintf` usage, format string vulnerabilities, hardcoded credentials, insecure use of `rand()`/`srand()`, missing null checks after `new`/`malloc`, and many pattern-based security issues. Semgrep's pattern matching is particularly effective at detecting command injection patterns and hardcoded secrets that cppcheck may miss.

---

## 5. Language-Specific Vulnerability Patterns

### 5.1 Command Injection (CWE-78)

**Pattern: `system()` with string concatenation**

```cpp
std::string cmd = "ping -c 3 " + host;
std::cout << exec_command(cmd) << std::endl;
// where exec_command calls popen(cmd.c_str(), "r")
```

**Pattern: Incomplete sanitization before shell execution**

```cpp
std::string sanitize_name(const std::string &name) {
    std::string safe = name;
    std::replace(safe.begin(), safe.end(), '/', '_');
    std::replace(safe.begin(), safe.end(), '\\', '_');
    return safe;  // ';', '|', '`' pass through
}
// ...
std::string cmd = "tar czf /tmp/" + safe_name + ".tar.gz " + filepath;
popen(cmd.c_str(), "r");
```

**Pattern: Interactive mode passing raw input to shell**

```cpp
std::getline(std::cin, input);
std::cout << exec_command(input) << std::endl;
// exec_command calls popen(input.c_str(), "r")
```

**Safe alternative:**

```cpp
// Use execvp with argument array — no shell interpretation
#include <unistd.h>
char *args[] = {"ping", "-c", "3", host.c_str(), nullptr};
execvp(args[0], args);
```

### 5.2 Broken Access Control (CWE-200, CWE-284, CWE-639)

**Pattern: No authentication on sensitive endpoint**

```cpp
svr.Get("/api/users/:id", [](const httplib::Request& req, httplib::Response& res) {
    // No auth check — returns SSN, salary to anyone
    int uid = std::stoi(req.path_params.at("id"));
    auto& user = users[uid];
    json resp = {{"ssn", user.ssn}, {"salary", user.salary}};
    res.set_content(resp.dump(), "application/json");
});
```

**Pattern: Client-controlled authorization header**

```cpp
auto it = req.headers.find("X-User-Role");
std::string role = (it != req.headers.end()) ? it->second : "employee";
if (role != "admin") {
    res.set_content(R"({"error":"Admin access required"})", "application/json");
    res.status = 403;
    return;
}
```

**Pattern: Missing object-level authorization**

```cpp
// Any authenticated user can access any record — no ownership check
auto it = records.find(record_id);
json resp = {{"content", it->second.content}};
res.set_content(resp.dump(), "application/json");
```

### 5.3 Cryptographic Failures (CWE-327, CWE-328, CWE-330)

**Pattern: `std::hash<>` used as cryptographic hash for passwords**

```cpp
static std::string md5_hash(const std::string& input) {
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h;
    return oss.str();  // Not a real MD5 — not cryptographic at all
}
users[1].password_hash = md5_hash("admin2024!");
```

**Pattern: XOR "encryption" with hardcoded key simulating DES-ECB**

```cpp
static const unsigned char DES_KEY[8] = {'s','3','c','r','3','t','!','!'};

static std::string des_xor_encrypt(const std::string& plaintext) {
    // ...
    for (size_t i = 0; i < padded.size(); i++) {
        encrypted[i] = padded[i] ^ DES_KEY[i % 8];  // XOR "encryption"
    }
    // ...
}
```

**Pattern: Predictable PRNG for session tokens**

```cpp
srand(static_cast<unsigned>(time(nullptr)));
std::ostringstream oss;
oss << std::hex << std::setfill('0')
    << std::setw(8) << rand()
    << std::setw(8) << rand();
std::string token = oss.str();
```

**Safe alternative:**

```cpp
#include <random>

// Use std::random_device for cryptographic randomness
std::random_device rd;
std::uniform_int_distribution<uint64_t> dist;
uint64_t token_part1 = dist(rd);
uint64_t token_part2 = dist(rd);

// For password hashing, use bcrypt or argon2 via a library
// For encryption, use OpenSSL AES-GCM
```

### 5.4 Insecure Design (CWE-209, CWE-522)

**Pattern: Plaintext password storage**

```cpp
users[1] = {1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", true};
```

**Pattern: Verbose error responses leaking credentials**

```cpp
json resp = {
    {"error", "Report generation failed"},
    {"details", "Could not connect to database as user '" + DB_USER + "' with password '" + DB_PASS + "'"}
};
res.set_content(resp.dump(), "application/json");
```

**Pattern: User enumeration via distinct error messages**

```cpp
// "No account found for username 'xyz'" vs. "Incorrect password"
// Allows attackers to enumerate valid usernames
```

**Pattern: Password reset token returned in response**

```cpp
json resp = {{"message", "Password reset link sent"}, {"token", reset_token}};
res.set_content(resp.dump(), "application/json");
```

### 5.5 Security Misconfiguration (CWE-16, CWE-611)

**Pattern: XXE via libxml2 with entity resolution (when used from C++)**

```cpp
xmlDocPtr doc = xmlReadMemory(body.c_str(), body.size(), "noname.xml", NULL,
                               XML_PARSE_NOERROR | XML_PARSE_DTDLOAD | XML_PARSE_NOENT);
```

**Pattern: Verbose server headers**

```cpp
res.set_header("Server", "cpp-httplib/0.14.0 (Linux)");
res.set_header("X-Powered-By", "cpp-httplib");
```

**Pattern: Overly permissive CORS**

```cpp
res.set_header("Access-Control-Allow-Origin", "*");
res.set_header("Access-Control-Allow-Credentials", "true");
```

**Pattern: Debug mode and TLS verification disabled**

```cpp
static bool debug_mode = true;
// HTTP client without SSL verification
httplib::SSLClient cli(host, port);
// Missing: cli.enable_server_certificate_verification(true);
```

**Safe alternative:**

```cpp
// Disable entity resolution in libxml2
xmlDocPtr doc = xmlReadMemory(body.c_str(), body.size(), "noname.xml", NULL,
                               XML_PARSE_NOERROR | XML_PARSE_NONET);
```

### 5.6 Vulnerable and Outdated Components (CWE-1104)

**Pattern: Linking against outdated header-only libraries**

```cpp
// Makefile or CMakeLists.txt references specific library versions that may have known CVEs
// -lmicrohttpd -lcurl -lxml2
// Header-only: httplib.h, json.hpp vendored without version tracking
```

**Pattern: Using HTTP client without SSL verification**

```cpp
httplib::Client cli(host, port);
cli.set_connection_timeout(10, 0);
auto res = cli.Get(path);
// No SSL verification configured
```

### 5.7 Auth Failures (CWE-287, CWE-307, CWE-798)

**Pattern: Hardcoded credentials**

```cpp
static const std::string ADMIN_API_KEY = "aak_prod_c4d5e6f7g8h9";
static const std::string SERVICE_PASSPHRASE = "svc-auth-bypass-2024";
```

**Pattern: Backdoor authentication bypass**

```cpp
if (username == "service" && password == ADMIN_API_KEY) {
    std::string token = create_session(0);
    // Bypasses normal authentication entirely
}
```

**Pattern: No rate limiting on authentication**

```cpp
// Login handler processes every request with no throttling
// No account lockout after failed attempts
svr.Post("/api/login", [](const httplib::Request& req, httplib::Response& res) {
    // ... no rate limiting logic ...
});
```

### 5.8 Logging and Monitoring Failures (CWE-778)

**Pattern: Credentials in API responses**

```cpp
json resp = {
    {"token", token}, {"user_id", uid}, {"role", user.role},
    {"password", user.password}, {"api_key", user.api_key}
};
res.set_content(resp.dump(), "application/json");
```

**Pattern: No audit logging for privilege changes**

```cpp
user.role = new_role;  // Role changed with no log entry
```

**Pattern: Data export leaking passwords**

```cpp
for (auto& [id, u] : users) {
    user_list.push_back({
        {"id", u.id}, {"username", u.username},
        {"password", u.password}, {"api_key", u.api_key}
    });
}
```

### 5.9 SSRF (CWE-918)

**Pattern: Unrestricted URL fetch via cpp-httplib**

```cpp
auto body = json::parse(req.body);
std::string url = body.value("url", "");
// No validation — fetches any URL including internal services
auto [status, content] = do_http_get(url);
```

**Pattern: Incomplete blocklist**

```cpp
if (parts.host == "localhost" || parts.host == "127.0.0.1") {
    res.set_content(R"({"error":"Blocked host"})", "application/json");
    res.status = 403;
    return;
}
// Missing: 0.0.0.0, [::1], 169.254.x.x, decimal IP representations, DNS rebinding
```

**Pattern: Open proxy via user-supplied base URL**

```cpp
std::string base_url = req.get_param_value("base_url");
std::string full_url = base_url + path;
auto [status, content] = do_http_get(full_url);
```

**Pattern: Webhook callback without internal network validation**

```cpp
// Only checks for http:// or https:// prefix
if (callback_url.substr(0, 7) != "http://" && callback_url.substr(0, 8) != "https://") {
    // reject
}
// No check for internal IPs, private ranges, or metadata endpoints
```

### 5.10 Out-of-Bounds Write (CWE-787)

**Pattern: `std::strcpy` into fixed-size char array in struct**

```cpp
void set_label(int index, const char *label) {
    std::strcpy(entries_[index].label, label);  // No bounds check on label length
}
```

**Pattern: Class method ingesting data without capacity check**

```cpp
void ingest(const double *data, int count) {
    for (int i = 0; i < count; i++) {
        buffer_[size_ + i] = data[i];  // No check: size_ + count <= capacity_
    }
    size_ += count;
}
```

**Pattern: Unbounded loop writing to fixed-size array**

```cpp
double readings[32];
int count = 0;
while (std::getline(stream, token, ',')) {
    readings[count] = std::stod(token);  // No upper bound check on count
    count++;
}
```

**Pattern: Integer overflow in allocation size**

```cpp
uint32_t total = num_entries * line_size;  // Overflow with large num_entries
char *report = new char[total];  // Undersized allocation
```

**Safe alternative:**

```cpp
// Use std::vector instead of raw arrays
std::vector<double> readings;
while (std::getline(stream, token, ',')) {
    readings.push_back(std::stod(token));  // Grows dynamically, bounds-safe
}

// Use std::string instead of char arrays
std::string label = input;  // No overflow possible
```

### 5.11 Use-After-Free (CWE-416)

**Pattern: Accessing object via raw pointer after deletion**

```cpp
Document *ref = store.get(1);
store.remove(1);  // Frees the document
std::cout << ref->title << std::endl;  // Use-after-free
```

**Pattern: Event bus holding dangling pointers**

```cpp
bus.subscribe(store.get(0), print_document_event);
bus.subscribe(store.get(1), print_document_event);
store.remove(1);  // Frees document at index 1
bus.publish();     // Calls handler with freed pointer
```

**Pattern: Shallow copy sharing internal buffer**

```cpp
Document *snapshot = new Document;
snapshot->content = doc->content;  // Shares raw pointer
store.remove(index);               // Frees doc->content
std::cout << snapshot->content;     // Use-after-free
```

**Pattern: Double-free via aliased raw pointer**

```cpp
char *content_ptr = d->content;
store.remove(0);           // Frees d->content via remove()
std::free(content_ptr);    // Double-free — same memory
```

**Safe alternative:**

```cpp
// Use std::shared_ptr for shared ownership
auto doc = std::make_shared<Document>();
// Or std::unique_ptr for exclusive ownership
auto doc = std::make_unique<Document>();
// Both prevent use-after-free and double-free
```

### 5.12 NULL Pointer Dereference (CWE-476)

**Pattern: Missing NULL check on lookup result**

```cpp
SensorReading *reading = registry.get_latest(rule.sensor_id);
double val = reading->value;  // Crashes if sensor_id not found
```

**Pattern: Dereferencing parse result without validation**

```cpp
SensorReading *parsed = parse_reading(line);
// parse_reading returns nullptr on malformed input
registry.record(parsed->sensor_id, parsed->value, parsed->timestamp, parsed->unit);
```

**Pattern: Comparing sensors that may not exist**

```cpp
SensorReading *r1 = registry.get_latest(id1);
SensorReading *r2 = registry.get_latest(id2);
double diff = r1->value - r2->value;  // Either may be nullptr
```

**Safe alternative:**

```cpp
SensorReading *reading = registry.get_latest(id);
if (reading) {
    double val = reading->value;  // Safe
}
// Or use std::optional<SensorReading> for value types
```

### 5.13 Integer Overflow (CWE-190)

**Pattern: Multiplication overflow in financial calculation**

```cpp
int compute_fee(const Transaction &txn) const {
    return txn.amount_cents * txn.fee_basis_points / 10000;
    // Overflows when amount_cents * fee_basis_points > INT_MAX
}
```

**Pattern: Overflow in allocation size computation**

```cpp
void *allocate_record_buffer(int record_count, int record_size) const {
    size_t total_bytes = static_cast<size_t>(record_count) * record_size;
    // If record_count * record_size overflows int before cast, total_bytes is wrong
    void *buffer = malloc(total_bytes);
}
```

**Pattern: Compound interest overflow**

```cpp
int compute_compound_interest(int principal_cents, int rate_bp, int periods) const {
    int current = principal_cents;
    for (int i = 0; i < periods; i++) {
        int interest = current * rate_bp / 10000;  // Overflows with large current
        current += interest;
    }
    return current;
}
```

**Pattern: Narrow-type overflow in hash**

```cpp
int16_t compute_short_hash(const std::string &data) const {
    int16_t hash = 0;
    for (char c : data) {
        hash = hash * 31 + static_cast<int16_t>(c);  // int16_t overflow
    }
    return hash;
}
```

**Safe alternative:**

```cpp
#include <cstdint>
#include <limits>

// Check for overflow before multiplication
if (record_count > 0 && static_cast<size_t>(record_size) > SIZE_MAX / record_count) {
    return nullptr;  // Would overflow
}
size_t total = static_cast<size_t>(record_count) * static_cast<size_t>(record_size);

// Use wider types for intermediate calculations
int64_t fee = static_cast<int64_t>(amount_cents) * fee_basis_points / 10000;
```

### 5.14 Race Conditions (CWE-362)

**Pattern: Check-then-act without locking**

```cpp
bool withdraw(long amount) {
    if (balance >= amount) {
        std::this_thread::yield();
        balance -= amount;  // Another thread may have changed balance
        return true;
    }
    return false;
}
```

**Pattern: Read-modify-write on shared counter**

```cpp
void increment() {
    long current = value;
    std::this_thread::yield();
    value = current + 1;  // Lost update
}
```

**Pattern: TOCTOU on inventory**

```cpp
bool placeOrder(const std::string &name, int qty) {
    if (it->second >= qty) {
        int stock = it->second;
        std::this_thread::yield();
        products[name] = stock - qty;  // Overselling
        return true;
    }
    return false;
}
```

**Pattern: Unsafe lazy singleton initialization**

```cpp
static LazyConfig *getInstance() {
    if (instance == nullptr) {
        std::this_thread::yield();
        instance = new LazyConfig();  // Multiple instances created
    }
    return instance;
}
```

**Safe alternative:**

```cpp
#include <mutex>

std::mutex mtx;

bool withdraw(long amount) {
    std::lock_guard<std::mutex> lock(mtx);
    if (balance >= amount) {
        balance -= amount;
        return true;
    }
    return false;
}

// For singletons, use C++11 magic statics (thread-safe by standard)
static LazyConfig& getInstance() {
    static LazyConfig instance;  // Thread-safe in C++11+
    return instance;
}
```

---

## 6. Cross-References to Examples

The table below maps each vulnerability class to the C++ source file and companion documentation in this project. All paths are relative to the `docs/` directory.

| Vulnerability Class | Source File | Companion Doc |
|---|---|---|
| Command Injection (CWE-78) | [`../injection/command-injection/cpp/main.cpp`](../injection/command-injection/cpp/main.cpp) | [`../injection/command-injection/cpp/main_SECURITY.md`](../injection/command-injection/cpp/main_SECURITY.md) |
| Broken Access Control (CWE-200, CWE-284, CWE-639) | [`../broken-access-control/cpp/main.cpp`](../broken-access-control/cpp/main.cpp) | [`../broken-access-control/cpp/main_SECURITY.md`](../broken-access-control/cpp/main_SECURITY.md) |
| Cryptographic Failures (CWE-327, CWE-328, CWE-330) | [`../cryptographic-failures/cpp/main.cpp`](../cryptographic-failures/cpp/main.cpp) | [`../cryptographic-failures/cpp/main_SECURITY.md`](../cryptographic-failures/cpp/main_SECURITY.md) |
| Insecure Design (CWE-209, CWE-522) | [`../insecure-design/cpp/main.cpp`](../insecure-design/cpp/main.cpp) | [`../insecure-design/cpp/main_SECURITY.md`](../insecure-design/cpp/main_SECURITY.md) |
| Security Misconfiguration (CWE-16, CWE-611) | [`../security-misconfiguration/cpp/main.cpp`](../security-misconfiguration/cpp/main.cpp) | [`../security-misconfiguration/cpp/main_SECURITY.md`](../security-misconfiguration/cpp/main_SECURITY.md) |
| Vulnerable Components (CWE-1104) | [`../vulnerable-components/cpp/main.cpp`](../vulnerable-components/cpp/main.cpp) | [`../vulnerable-components/cpp/main_SECURITY.md`](../vulnerable-components/cpp/main_SECURITY.md) |
| Auth Failures (CWE-287, CWE-307, CWE-798) | [`../auth-failures/cpp/main.cpp`](../auth-failures/cpp/main.cpp) | [`../auth-failures/cpp/main_SECURITY.md`](../auth-failures/cpp/main_SECURITY.md) |
| Logging/Monitoring Failures (CWE-778) | [`../logging-monitoring-failures/cpp/main.cpp`](../logging-monitoring-failures/cpp/main.cpp) | [`../logging-monitoring-failures/cpp/main_SECURITY.md`](../logging-monitoring-failures/cpp/main_SECURITY.md) |
| SSRF (CWE-918) | [`../ssrf/cpp/main.cpp`](../ssrf/cpp/main.cpp) | [`../ssrf/cpp/main_SECURITY.md`](../ssrf/cpp/main_SECURITY.md) |
| Out-of-Bounds Write (CWE-787) | [`../memory-safety/out-of-bounds-write/cpp/main.cpp`](../memory-safety/out-of-bounds-write/cpp/main.cpp) | [`../memory-safety/out-of-bounds-write/cpp/main_SECURITY.md`](../memory-safety/out-of-bounds-write/cpp/main_SECURITY.md) |
| Use After Free (CWE-416) | [`../memory-safety/use-after-free/cpp/main.cpp`](../memory-safety/use-after-free/cpp/main.cpp) | [`../memory-safety/use-after-free/cpp/main_SECURITY.md`](../memory-safety/use-after-free/cpp/main_SECURITY.md) |
| NULL Pointer Dereference (CWE-476) | [`../memory-safety/null-pointer-deref/cpp/main.cpp`](../memory-safety/null-pointer-deref/cpp/main.cpp) | [`../memory-safety/null-pointer-deref/cpp/main_SECURITY.md`](../memory-safety/null-pointer-deref/cpp/main_SECURITY.md) |
| Integer Overflow (CWE-190) | [`../integer-overflow/cpp/main.cpp`](../integer-overflow/cpp/main.cpp) | [`../integer-overflow/cpp/main_SECURITY.md`](../integer-overflow/cpp/main_SECURITY.md) |
| Race Condition (CWE-362) | [`../race-condition/cpp/main.cpp`](../race-condition/cpp/main.cpp) | [`../race-condition/cpp/main_SECURITY.md`](../race-condition/cpp/main_SECURITY.md) |

---

## 7. Quick-Reference Checklist

Use this checklist during C++ code reviews. Each item maps to a vulnerability class covered in this guide.

- [ ] **No `system()`/`popen()` with user input** — Shell commands are constructed without user-controlled data, or `execvp()` with argument arrays is used instead
- [ ] **Prefer `std::string` and `std::vector`** — Raw `char[]` buffers and C-style arrays are avoided; when used, all copies are bounds-checked
- [ ] **Bounded string operations** — `std::strncpy`/`std::snprintf` are used instead of `std::strcpy`/`std::sprintf`; destination buffers are always null-terminated
- [ ] **`memcpy` length validated** — All `std::memcpy`/`std::memmove` calls verify that the length does not exceed the destination buffer size
- [ ] **Smart pointers for ownership** — `std::unique_ptr` or `std::shared_ptr` are used instead of raw `new`/`delete`; no raw pointer aliases outlive the owning smart pointer
- [ ] **No use-after-free** — No pointer or reference is used after the object it refers to has been freed, moved, or erased from a container
- [ ] **No double-free** — Each allocated block is freed exactly once; raw pointer aliases to smart-pointer-managed memory are not manually freed
- [ ] **`new[]`/`delete[]` matched** — Array allocations use `delete[]`, not `delete`; `malloc`/`free` are not mixed with `new`/`delete`
- [ ] **Integer overflow checks** — Multiplications used for allocation sizes or array indices are checked for overflow before use; `static_cast<size_t>` is applied before multiplication, not after
- [ ] **Signed/unsigned conversions** — Casts between signed and unsigned types are explicit and validated; `std::stoi`/`std::stol` results are range-checked before narrowing
- [ ] **NULL/nullptr checks** — Every pointer returned from a lookup, parse, or allocation function is checked for `nullptr` before dereferencing
- [ ] **Authentication on every endpoint** — All sensitive HTTP endpoints verify the session/token before processing
- [ ] **Server-side authorization** — Role and permission checks use server-side session data, not client-supplied headers
- [ ] **Object-level access control** — Resource access verifies the requesting user owns or is authorized for the specific resource
- [ ] **Strong password hashing** — Passwords are hashed with bcrypt, argon2, or scrypt — never MD5, SHA-1, or `std::hash<>`
- [ ] **Modern encryption** — AES-GCM or AES-CBC with HMAC is used; no DES, no ECB mode, no XOR "encryption"
- [ ] **Cryptographic randomness** — Tokens and secrets use `std::random_device`, `RAND_bytes()`, or `getrandom()` — not `rand()`/`srand()`
- [ ] **No hardcoded secrets** — API keys, passwords, and encryption keys are loaded from environment variables or a secrets manager, not compiled into the binary
- [ ] **SSRF protection** — Outbound HTTP requests validate URLs against an allowlist; internal/metadata IPs are blocked comprehensively (including `0.0.0.0`, `[::1]`, `169.254.x.x`)
- [ ] **Minimal error responses** — Error responses do not include stack traces, database credentials, or internal configuration
- [ ] **No debug mode in production** — Debug flags, verbose logging, and diagnostic endpoints are disabled or protected
- [ ] **Secure CORS** — `Access-Control-Allow-Origin` is set to specific trusted origins, not `*`
- [ ] **XXE prevention** — XML parsers disable DTD loading and entity resolution (`XML_PARSE_NONET`, no `XML_PARSE_DTDLOAD`)
- [ ] **Audit logging** — Authentication events, privilege changes, and sensitive operations are logged
- [ ] **No credentials in responses** — API responses do not include passwords, API keys, or other secrets
- [ ] **Thread safety** — Shared mutable state accessed by multiple threads uses `std::mutex`, `std::lock_guard`, or `std::atomic`; singletons use `std::call_once` or C++11 static locals
- [ ] **Dependency hygiene** — Linked libraries and header-only dependencies are version-pinned; dependencies are checked for known CVEs
