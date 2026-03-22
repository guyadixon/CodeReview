# Go Security Code Review Guide

## 1. Introduction

This guide provides a structured approach to security-focused code review for Go applications. It is designed for both beginners learning to identify security vulnerabilities in Go code and experienced developers looking for a language-specific checklist to streamline their reviews.

Go's strong type system, built-in concurrency primitives, and opinionated standard library make it a popular choice for backend services and infrastructure tooling. However, Go's simplicity can mask subtle security issues — unchecked errors, goroutine data races, unsafe pointer usage, and the ease of shelling out via `os/exec` all create attack surface that requires careful review. This guide covers manual review strategies, common anti-patterns, recommended tooling, and vulnerability patterns organized by class, with cross-references to the intentionally vulnerable examples in this project.

**Audience:** Security trainees, application developers, code reviewers, and anyone evaluating Go codebases for security weaknesses.

---

## 2. Manual Review Best Practices

### 2.1 Trace Data from Entry to Sink

Go web frameworks (Gin, Echo, net/http) accept user input through query parameters (`c.Query()`), path parameters (`c.Param()`), JSON body binding (`c.ShouldBindJSON()`), headers (`c.GetHeader()`), and cookies. Trace every external input to where it is consumed — database queries, shell commands, HTTP responses, outbound HTTP requests, or file operations. Any path from source to sink without validation or sanitization is a potential vulnerability.

### 2.2 Inspect String Formatting in Sensitive Contexts

Go's `fmt.Sprintf`, string concatenation (`+`), and `strings.Builder` are frequently used to construct SQL queries, shell commands, HTML output, and URLs. When any of these are used with user-controlled data in a security-sensitive context, treat it as a high-priority finding. Pay special attention to `fmt.Sprintf` calls inside loops that build query clauses incrementally.

### 2.3 Review Import Statements

Scan imports for packages known to introduce risk:
- `os/exec` — command injection when used with `sh -c` and string interpolation
- `crypto/md5`, `crypto/sha1`, `crypto/des` — weak or broken cryptographic algorithms
- `math/rand` — non-cryptographic PRNG, unsuitable for tokens or secrets
- `encoding/gob` — deserialization of untrusted data can cause DoS or unexpected type instantiation
- `plugin` — loading shared objects executes arbitrary code via init functions
- `unsafe` — bypasses Go's type safety and memory safety guarantees
- `runtime/debug` — `debug.Stack()` in HTTP responses leaks internal details

### 2.4 Check for Hardcoded Secrets

Search for string literals that look like passwords, API keys, tokens, or connection strings. Common patterns include package-level `var` or `const` declarations with names like `apiKey`, `secretKey`, `password`, `dbDSN`, or connection strings containing `user:pass@host`.

### 2.5 Examine Error Handling

Go's explicit error handling (`if err != nil`) is a strength, but review how errors are surfaced. Look for:
- `debug.Stack()` returned in HTTP responses
- Raw `err.Error()` messages sent to clients (may contain DSN, file paths, or internal details)
- Errors silently discarded with `_` — especially from `exec.Command`, crypto operations, or database calls

### 2.6 Evaluate Cryptographic Choices

Flag uses of `crypto/md5` or `crypto/sha1` for password hashing or integrity verification. Check for `crypto/des`, ECB-mode implementations (manual block-by-block encryption), and hardcoded encryption keys. Verify that `math/rand` (not `crypto/rand`) is not used for session tokens, API keys, or other security-sensitive values.

### 2.7 Assess Access Control Logic

For every Gin/Echo handler, verify:
- Authentication is checked before any business logic executes
- Authorization checks use server-side session data, not client-supplied headers (e.g., `X-User-Role`)
- Object-level access control prevents users from accessing resources belonging to others (IDOR)
- Sensitive struct fields are excluded from JSON serialization (use separate response structs or `json:"-"` tags)

### 2.8 Review Concurrency Patterns

Go's goroutines make concurrency easy but data races subtle. Look for:
- Shared struct fields or map entries accessed by multiple goroutines without `sync.Mutex`, `sync.RWMutex`, or `sync/atomic`
- Check-then-act patterns (read a value, make a decision, then modify) without holding a lock
- Package-level variables modified by concurrent handlers
- Singleton initialization without `sync.Once`

### 2.9 Review Configuration Defaults

Check for `gin.SetMode(gin.DebugMode)`, permissive CORS (`Access-Control-Allow-Origin` reflecting any origin), `Server` or `X-Powered-By` headers exposing version information, and unauthenticated settings or diagnostics endpoints.

---

## 3. Common Security Pitfalls

### 3.1 Injection

| Anti-Pattern | Risk |
|---|---|
| `"SELECT * FROM t WHERE x = '" + userInput + "'"` | SQL injection via string concatenation |
| `fmt.Sprintf("SELECT ... WHERE status = '%s'", status)` | SQL injection via `Sprintf` |
| `fmt.Sprintf("... ORDER BY %s %s", col, dir)` with unvalidated `dir` | SQL injection via ORDER BY clause |
| Loop building SQL with `fmt.Sprintf` per iteration | SQL injection in dynamic query builder |
| `exec.Command("sh", "-c", "ping -c 3 " + host)` | Command injection via shell execution |
| `exec.Command("sh", "-c", fmt.Sprintf("dig %s %s", rt, domain))` | Command injection via `Sprintf` in helper |
| `fmt.Sprintf("tail -n %s %s \| grep '%s'", lines, path, kw)` | Multi-parameter injection in shell pipeline |
| `fmt.Sprintf("<h2>%s</h2>", userInput)` in HTML response | Reflected and stored XSS |
| `fmt.Sprintf("%s(%s)", callback, data)` for JSONP | XSS via JSONP callback injection |

### 3.2 Broken Access Control

| Anti-Pattern | Risk |
|---|---|
| Handler returns full struct via `c.JSON(200, user)` including SSN, salary | Excessive data exposure via JSON tags |
| `c.GetHeader("X-User-Role")` used for authorization | Client-controlled role spoofing |
| No ownership check on resource access after authentication | IDOR — any authenticated user accesses any resource |
| Role update endpoint with authentication but no admin check | Privilege escalation |
| Debug/config endpoints with no authentication | Credential and secret leakage |

### 3.3 Cryptographic Failures

| Anti-Pattern | Risk |
|---|---|
| `crypto/des` with manual block-by-block encryption | DES in ECB mode — broken cipher |
| `desKey = []byte("s3cr3t!!")` at package level | Hardcoded encryption key |
| `crypto/md5` for password hashing | Weak, unsalted password hash |
| MD5 concatenation for integrity signatures | Collision-vulnerable integrity check |
| `math/rand` seeded with `time.Now().Unix()` for tokens | Predictable PRNG |
| SHA-1 hash of `"tkn-{seq}-{timestamp}"` for API tokens | Predictable token generation |

### 3.4 Insecure Design

| Anti-Pattern | Risk |
|---|---|
| Database DSN with credentials as package-level `var` | Hardcoded infrastructure credentials |
| `debug.Stack()` and DSN returned in error JSON response | Stack trace and credential leakage |
| `c.JSON(200, user)` where User struct has `json:"password"` tag | Password exposure via struct serialization |
| Password reset token returned in API response body | Token leakage — bypasses email verification |
| Config endpoint returning DSN and SMTP credentials | Credential exposure through API |

### 3.5 Security Misconfiguration

| Anti-Pattern | Risk |
|---|---|
| `gin.SetMode(gin.DebugMode)` | Debug mode in production |
| `c.Header("Server", "Go/1.21 Gin/1.9")` | Technology fingerprinting |
| Origin reflection into `Access-Control-Allow-Origin` with credentials | Overly permissive CORS |
| `xml.NewDecoder` with `Strict = false` | Relaxed XML parsing (defense-in-depth failure) |
| `debug.Stack()` in error handler responses | Stack trace information disclosure |
| Unauthenticated settings endpoint accepting arbitrary key-value pairs | Security control manipulation |
| `os.Environ()` returned in diagnostics endpoint | Environment variable leakage |

### 3.6 Vulnerable Components

| Anti-Pattern | Risk |
|---|---|
| Outdated Gin version in `go.mod` | Known framework vulnerabilities |
| `gopkg.in/yaml.v2` instead of `yaml.v3` | Legacy YAML parser with known issues |
| Outdated `golang.org/x/crypto` transitive dependency | Missing security patches |
| Outdated `go-playground/validator` | Input validation bypass |

### 3.7 Auth Failures

| Anti-Pattern | Risk |
|---|---|
| `const internalAPIKey = "iak_prod_..."` | Hardcoded API key |
| `crypto/md5` for password hashing in auth flow | Weak password storage |
| No rate limiting on login endpoint | Brute-force and credential stuffing |
| Hardcoded debug access code accepted as valid token | Authentication bypass backdoor |
| Debug endpoint returning active session tokens | Session hijacking |

### 3.8 Integrity Failures (Deserialization)

| Anti-Pattern | Risk |
|---|---|
| `gob.NewDecoder(reader).Decode(&target)` on untrusted input | DoS via crafted gob payloads |
| `plugin.Open(path)` on downloaded `.so` file | Arbitrary code execution via plugin loading |
| `exec.Command("sh", "-c", body.Script+" "+body.Args)` | Direct shell command injection |
| Gob-encoded data stored and retrieved without integrity check | Tampered deserialization |

### 3.9 Logging and Monitoring Failures

| Anti-Pattern | Risk |
|---|---|
| Login handler with no `log.Printf` calls | Failed auth attempts go undetected |
| Successful login returns password and API key in response | Credential leakage |
| Role change endpoint with no audit logging | Silent privilege escalation |
| Financial transactions with no persistent audit log | Fraud goes undetected |
| Data export endpoint with no access logging | Mass exfiltration invisible |

### 3.10 SSRF

| Anti-Pattern | Risk |
|---|---|
| `http.Client.Get(userURL)` without validation | Unrestricted SSRF |
| Blocklist checking only `localhost` and `127.0.0.1` | SSRF blocklist bypass via `[::1]`, `0.0.0.0`, etc. |
| Webhook callback URL fetched without re-validation | Two-step SSRF |
| Hostname string check instead of resolved IP validation | DNS rebinding bypass |
| Service proxy with user-supplied `base_url` fallback | Open relay to internal services |

### 3.11 Race Conditions

| Anti-Pattern | Risk |
|---|---|
| Read-sleep-write on shared struct field without mutex | Lost updates (deposits, counters) |
| `if balance >= amount` then sleep then `balance -= amount` | TOCTOU — overdraw / double-spend |
| Cross-account transfer modifying two structs without locks | Money creation/destruction |
| `if available > 0` then sleep then `available--` | Ticket overselling |
| Map read-check-write without synchronization | Inventory overselling |
| Singleton `if instance == nil` without `sync.Once` | Multiple instances, data loss |

### 3.12 Null Pointer Dereference

| Anti-Pattern | Risk |
|---|---|
| Map lookup returning `nil` pointer, then `m.Value` without check | Panic — denial of service |
| Map lookup returning `nil` function, then `fn()` call | Panic — nil function call |
| Function returning `nil` on parse error, caller dereferences fields | Panic on malformed input |
| Nil check on wrong variable in conditional (`best == nil \|\| m.Value > best.Value`) | Masked nil dereference |

### 3.13 Integer Overflow

| Anti-Pattern | Risk |
|---|---|
| `int32 * int32` without widening to `int64` | Silent wraparound — incorrect calculations |
| Intermediate `int64` result cast back to `int32` on return | Truncation — data loss |
| Negative check (`< 0`) as overflow guard | Incomplete — overflow can produce small positive values |


---

## 4. Recommended SAST Tools & Linters

### 4.1 gosec

gosec (Go Security Checker) is a Go-specific static analysis tool that inspects Go source code for security issues by scanning the AST.

**Installation:**

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

**Basic usage — scan a single directory:**

```bash
gosec ./injection/sql-injection/go/...
```

**Scan the entire project recursively:**

```bash
gosec ./security-bug-examples/...
```

**Generate a JSON report:**

```bash
gosec -fmt=json -out=gosec_report.json ./security-bug-examples/...
```

**Filter by severity (medium and above):**

```bash
gosec -severity=medium ./security-bug-examples/...
```

**Exclude specific rules:**

```bash
gosec -exclude=G104 ./security-bug-examples/...
```

**What gosec catches:** Use of `exec.Command` with `sh -c`, `crypto/md5` and `crypto/des` usage, hardcoded credentials, `math/rand` for security-sensitive operations, SQL string concatenation, binding to `0.0.0.0`, unhandled errors, and weak TLS configurations.

### 4.2 staticcheck

staticcheck is a state-of-the-art Go linter that finds bugs, performance issues, and code simplifications. Its SA (static analysis) checks include several security-relevant rules.

**Installation:**

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
```

**Basic usage — scan a package:**

```bash
staticcheck ./injection/command-injection/go/...
```

**Scan the entire project:**

```bash
staticcheck ./security-bug-examples/...
```

**Show only specific check categories:**

```bash
staticcheck -checks "SA*" ./security-bug-examples/...
```

**Output in JSON format:**

```bash
staticcheck -f json ./security-bug-examples/...
```

**What staticcheck catches:** Deprecated function usage, incorrect use of `sync` primitives, unreachable code, unused results of important function calls, and various code patterns that indicate bugs. While not security-focused, its SA checks complement gosec by catching code quality issues that can have security implications.

### 4.3 Semgrep

Semgrep is a multi-language static analysis tool with pattern-based rules. It supports custom rules and has a large community rule registry with Go-specific security rules.

**Installation:**

```bash
pip install semgrep
# or
brew install semgrep
```

**Scan with the default Go security ruleset:**

```bash
semgrep --config "p/golang" security-bug-examples/
```

**Scan with OWASP Top 10 rules:**

```bash
semgrep --config "p/owasp-top-ten" security-bug-examples/
```

**Scan a single file:**

```bash
semgrep --config "p/golang" injection/sql-injection/go/main.go
```

**Run with auto configuration (recommended for first-time scans):**

```bash
semgrep --config auto security-bug-examples/
```

**What Semgrep catches:** SQL injection patterns in Go (string concatenation in `db.Query`), command injection via `exec.Command` with shell, SSRF patterns with `http.Client`, insecure cryptographic usage, hardcoded secrets, and many framework-specific issues. Semgrep's pattern matching is particularly effective at detecting `fmt.Sprintf`-based injection that gosec may miss in complex expressions.

---

## 5. Language-Specific Vulnerability Patterns

### 5.1 SQL Injection (CWE-89)

**Pattern: String concatenation in queries**

```go
// Vulnerable — user input concatenated directly
keyword := c.Query("q")
query := "SELECT id, name FROM products WHERE name LIKE '%" + keyword + "%'"
rows, err := db.Query(query)
```

**Pattern: `fmt.Sprintf` in query construction**

```go
// Vulnerable — Sprintf builds WHERE clause from user input
status := c.Query("status")
query += fmt.Sprintf(" AND status = '%s'", status)
```

**Pattern: Unvalidated ORDER BY injection**

```go
// Vulnerable — sortDir not validated against allowlist
query := fmt.Sprintf("SELECT * FROM products ORDER BY %s %s", sortCol, sortDir)
```

**Pattern: Loop-based query building with Sprintf**

```go
// Vulnerable — each tag injected via Sprintf inside loop
tags := strings.Split(c.Query("tags"), ",")
for _, tag := range tags {
    query += fmt.Sprintf(" AND name LIKE '%%%s%%'", strings.TrimSpace(tag))
}
```

**Safe alternative:**

```go
rows, err := db.Query("SELECT id, name FROM products WHERE name LIKE ?", "%"+keyword+"%")
```

### 5.2 Command Injection (CWE-78)

**Pattern: `exec.Command` with `sh -c` and concatenation**

```go
cmd := exec.Command("sh", "-c", "ping -c 3 "+host)
```

**Pattern: `exec.Command` with `sh -c` and `fmt.Sprintf`**

```go
cmdStr := fmt.Sprintf("dig %s %s +short", recordType, domain)
cmd := exec.Command("sh", "-c", cmdStr)
```

**Pattern: Shell pipeline with multiple injection points**

```go
cmdStr := fmt.Sprintf("tail -n %s %s | grep '%s'", lines, logPath, keyword)
cmd := exec.Command("sh", "-c", cmdStr)
```

**Safe alternative:**

```go
// Use argument list — no shell interpretation
cmd := exec.Command("ping", "-c", "3", host)
```

### 5.3 Cross-Site Scripting — XSS (CWE-79)

**Pattern: Reflected XSS via `fmt.Sprintf` in HTML**

```go
// Vulnerable — query parameter embedded without escaping
tag := c.Query("tag")
html := fmt.Sprintf("<p>Filtering by tag: <strong>%s</strong></p>", tag)
```

**Pattern: Stored XSS via struct fields in HTML**

```go
// Vulnerable — stored post content rendered without escaping
html := fmt.Sprintf("<h2>%s</h2><div>%s</div>", post.Title, post.Content)
```

**Pattern: XSS via `href` attribute (javascript: protocol)**

```go
html := fmt.Sprintf(`<a href="%s">%s</a>`, profile.Website, profile.Website)
```

**Pattern: JSONP callback injection**

```go
callback := c.Query("callback")
response := fmt.Sprintf("%s(%s)", callback, string(jsonData))
c.Data(200, "application/javascript", []byte(response))
```

**Safe alternative:**

```go
import "html"
safe := html.EscapeString(userInput)
output := fmt.Sprintf("<p>%s</p>", safe)
```

### 5.4 Broken Access Control (CWE-200, CWE-284, CWE-639)

**Pattern: No authentication on sensitive endpoint**

```go
func getUserProfile(c *gin.Context) {
    id, _ := strconv.Atoi(c.Param("id"))
    user := users[id]
    c.JSON(200, user) // Returns SSN, salary — no auth check
}
```

**Pattern: Client-controlled authorization header**

```go
role := c.GetHeader("X-User-Role")
if role != "admin" {
    c.JSON(403, gin.H{"error": "Admin access required"})
    return
}
```

**Pattern: Missing object-level authorization**

```go
// Any authenticated user can access any ticket — no ownership check
ticket := tickets[ticketID]
c.JSON(200, ticket) // Includes internal_notes
```

### 5.5 Cryptographic Failures (CWE-327, CWE-328, CWE-330)

**Pattern: DES in ECB mode with hardcoded key**

```go
var desKey = []byte("s3cr3t!!")
block, _ := des.NewCipher(desKey)
// Manual block-by-block encryption — ECB mode
for i := 0; i < len(padded); i += des.BlockSize {
    block.Encrypt(encrypted[i:i+des.BlockSize], padded[i:i+des.BlockSize])
}
```

**Pattern: MD5 for password hashing**

```go
hash := md5.Sum([]byte(password))
return hex.EncodeToString(hash[:])
```

**Pattern: Predictable PRNG for session tokens**

```go
src := rand.NewSource(time.Now().Unix())
rng := rand.New(src)
// Generates "random" token from predictable seed
```

**Safe alternative:**

```go
import "golang.org/x/crypto/bcrypt"
hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

import "crypto/rand"
b := make([]byte, 32)
crypto_rand.Read(b)
token := hex.EncodeToString(b)
```

### 5.6 Insecure Design (CWE-209, CWE-522)

**Pattern: Hardcoded credentials in package-level variables**

```go
var dbDSN = "host=db.internal port=5432 user=appuser password=Pg_Pr0d#2024 dbname=mydb"
```

**Pattern: Stack trace and DSN in error response**

```go
c.JSON(500, gin.H{
    "error":    err.Error(),
    "trace":    string(debug.Stack()),
    "database": dbDSN,
})
```

**Pattern: Password reset token returned in response**

```go
c.JSON(200, gin.H{
    "message":     "Reset email sent",
    "reset_token": token,       // Should only be sent via email
    "smtp_server": smtpHost,    // Leaks internal infrastructure
})
```

### 5.7 Security Misconfiguration (CWE-16, CWE-611)

**Pattern: Debug mode and version disclosure**

```go
gin.SetMode(gin.DebugMode)
c.Header("Server", fmt.Sprintf("Go/%s Gin/%s", runtime.Version(), gin.Version))
```

**Pattern: Overly permissive CORS**

```go
origin := c.GetHeader("Origin")
if origin == "" { origin = "*" }
c.Header("Access-Control-Allow-Origin", origin)
c.Header("Access-Control-Allow-Credentials", "true")
```

**Pattern: Relaxed XML parsing**

```go
decoder := xml.NewDecoder(strings.NewReader(rawXML))
decoder.Strict = false // Accepts malformed XML
```

### 5.8 Vulnerable and Outdated Components (CWE-1104)

**Pattern: Outdated dependencies in go.mod**

```
require (
    github.com/gin-gonic/gin v1.7.4          // Known CVEs
    gopkg.in/yaml.v2 v2.4.0                  // Legacy, use yaml.v3
)
```

**Detection approach:**

```bash
# Use govulncheck for vulnerability scanning
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Use nancy for dependency auditing
go list -json -deps ./... | nancy sleuth
```

### 5.9 Integrity Failures — Deserialization (CWE-502, CWE-829)

**Pattern: Gob deserialization of untrusted input**

```go
decoded, _ := base64.StdEncoding.DecodeString(payload)
dec := gob.NewDecoder(bytes.NewReader(decoded))
dec.Decode(&target) // Crafted payloads can cause DoS
```

**Pattern: Remote plugin loading**

```go
resp, _ := http.Get(pluginURL)
data, _ := io.ReadAll(resp.Body)
os.WriteFile(path, data, 0755)
p, _ := plugin.Open(path) // Executes init() — arbitrary code execution
```

**Pattern: Shell command execution from user input**

```go
cmd := exec.Command("sh", "-c", body.Script+" "+body.Args)
```

### 5.10 Logging and Monitoring Failures (CWE-778)

**Pattern: No logging of authentication events**

```go
func handleLogin(c *gin.Context) {
    // ... validates credentials ...
    if user.Password != hash(body.Password) {
        c.JSON(401, gin.H{"error": "Invalid credentials"})
        return // No log.Printf — brute force invisible
    }
    c.JSON(200, gin.H{"token": token})
    // No log of successful login either
}
```

**Pattern: Credentials in API responses**

```go
c.JSON(200, gin.H{
    "token":    token,
    "password": user.Password,  // Plaintext password in response
    "api_key":  user.APIKey,    // API key in response
})
```

### 5.11 SSRF (CWE-918)

**Pattern: Unrestricted URL fetch**

```go
resp, err := http.Get(userSuppliedURL) // No validation
```

**Pattern: Incomplete blocklist**

```go
blocked := map[string]bool{"localhost": true, "127.0.0.1": true}
// Missing: [::1], 0.0.0.0, 169.254.169.254, 10.x.x.x, 172.16.x.x, 192.168.x.x
```

**Pattern: Hostname check instead of resolved IP check (DNS rebinding)**

```go
if strings.HasPrefix(parsed.Hostname(), "169.254") {
    // Bypassable via DNS rebinding — domain resolves to safe IP first, then 169.254.x.x
}
```

**Safe alternative:**

```go
ips, _ := net.LookupIP(parsed.Hostname())
for _, ip := range ips {
    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
        c.JSON(403, gin.H{"error": "Blocked destination"})
        return
    }
}
```

### 5.12 Race Conditions (CWE-362)

**Pattern: Check-then-act without locking**

```go
func (a *BankAccount) Withdraw(amount int64) bool {
    if a.Balance >= amount {
        time.Sleep(time.Millisecond) // Simulates processing delay
        a.Balance -= amount          // Another goroutine may have changed balance
        return true
    }
    return false
}
```

**Pattern: Non-atomic read-modify-write on shared map**

```go
stock := inv.Products[name]
if stock >= qty {
    time.Sleep(time.Millisecond)
    inv.Products[name] = stock - qty // Lost update
}
```

**Pattern: Broken singleton without sync.Once**

```go
func GetConfig() *Config {
    if configInstance == nil {
        time.Sleep(time.Millisecond)
        configInstance = &Config{} // Multiple goroutines create separate instances
    }
    return configInstance
}
```

**Safe alternative:**

```go
var mu sync.Mutex

func (a *BankAccount) Withdraw(amount int64) bool {
    mu.Lock()
    defer mu.Unlock()
    if a.Balance >= amount {
        a.Balance -= amount
        return true
    }
    return false
}

// Or use sync.Once for singletons
var once sync.Once
func GetConfig() *Config {
    once.Do(func() { configInstance = &Config{} })
    return configInstance
}
```

### 5.13 Null Pointer Dereference (CWE-476)

**Pattern: Unchecked map lookup returning nil pointer**

```go
m := store.Get(name) // Returns nil if name not in map
total += m.Value     // Panic: nil pointer dereference
```

**Pattern: Nil function call from map lookup**

```go
fn := widgets[name] // Returns nil func if name not in map
return fn()         // Panic: nil function call
```

**Pattern: Nil check on wrong variable**

```go
// best is checked for nil, but m is not — m can be nil when best is non-nil
if best == nil || m.Value > best.Value {
    best = m
}
```

**Safe alternative:**

```go
m := store.Get(name)
if m == nil {
    continue // or return error
}
total += m.Value
```

### 5.14 Integer Overflow (CWE-190)

**Pattern: int32 multiplication without widening**

```go
func ComputeCharge(rate int32, nights int32) int32 {
    return rate * nights // Silently wraps on overflow
}
```

**Pattern: Correct intermediate but truncated return**

```go
func convert(amount int32, rate int32) int32 {
    intermediate := int64(amount) * int64(rate) // Correct
    return int32(intermediate / 1000000)         // Truncation!
}
```

**Pattern: Incomplete overflow guard**

```go
totalSize := rooms * dataPerRoom
if totalSize < 0 { return nil } // Misses overflow to small positive values
```

**Safe alternative:**

```go
func ComputeCharge(rate int32, nights int32) int64 {
    return int64(rate) * int64(nights)
}
```

---

## 6. Cross-References to Examples

The table below maps each vulnerability class to the Go source file and companion documentation in this project. All paths are relative to the `docs/` directory.

| Vulnerability Class | Source File | Companion Doc |
|---|---|---|
| SQL Injection (CWE-89) | [`../injection/sql-injection/go/main.go`](../injection/sql-injection/go/main.go) | [`../injection/sql-injection/go/main_SECURITY.md`](../injection/sql-injection/go/main_SECURITY.md) |
| Command Injection (CWE-78) | [`../injection/command-injection/go/main.go`](../injection/command-injection/go/main.go) | [`../injection/command-injection/go/main_SECURITY.md`](../injection/command-injection/go/main_SECURITY.md) |
| Cross-Site Scripting (CWE-79) | [`../injection/xss/go/main.go`](../injection/xss/go/main.go) | [`../injection/xss/go/main_SECURITY.md`](../injection/xss/go/main_SECURITY.md) |
| Broken Access Control (CWE-200, CWE-284, CWE-639) | [`../broken-access-control/go/main.go`](../broken-access-control/go/main.go) | [`../broken-access-control/go/main_SECURITY.md`](../broken-access-control/go/main_SECURITY.md) |
| Cryptographic Failures (CWE-327, CWE-328, CWE-330) | [`../cryptographic-failures/go/main.go`](../cryptographic-failures/go/main.go) | [`../cryptographic-failures/go/main_SECURITY.md`](../cryptographic-failures/go/main_SECURITY.md) |
| Insecure Design (CWE-209, CWE-522) | [`../insecure-design/go/main.go`](../insecure-design/go/main.go) | [`../insecure-design/go/main_SECURITY.md`](../insecure-design/go/main_SECURITY.md) |
| Security Misconfiguration (CWE-16, CWE-611) | [`../security-misconfiguration/go/main.go`](../security-misconfiguration/go/main.go) | [`../security-misconfiguration/go/main_SECURITY.md`](../security-misconfiguration/go/main_SECURITY.md) |
| Vulnerable Components (CWE-1104) | [`../vulnerable-components/go/main.go`](../vulnerable-components/go/main.go) | [`../vulnerable-components/go/main_SECURITY.md`](../vulnerable-components/go/main_SECURITY.md) |
| Auth Failures (CWE-287, CWE-307, CWE-798) | [`../auth-failures/go/main.go`](../auth-failures/go/main.go) | [`../auth-failures/go/main_SECURITY.md`](../auth-failures/go/main_SECURITY.md) |
| Integrity Failures (CWE-502, CWE-829) | [`../integrity-failures/go/main.go`](../integrity-failures/go/main.go) | [`../integrity-failures/go/main_SECURITY.md`](../integrity-failures/go/main_SECURITY.md) |
| Logging/Monitoring Failures (CWE-778) | [`../logging-monitoring-failures/go/main.go`](../logging-monitoring-failures/go/main.go) | [`../logging-monitoring-failures/go/main_SECURITY.md`](../logging-monitoring-failures/go/main_SECURITY.md) |
| SSRF (CWE-918) | [`../ssrf/go/main.go`](../ssrf/go/main.go) | [`../ssrf/go/main_SECURITY.md`](../ssrf/go/main_SECURITY.md) |
| NULL Pointer Dereference (CWE-476) | [`../memory-safety/null-pointer-deref/go/main.go`](../memory-safety/null-pointer-deref/go/main.go) | [`../memory-safety/null-pointer-deref/go/main_SECURITY.md`](../memory-safety/null-pointer-deref/go/main_SECURITY.md) |
| Integer Overflow (CWE-190) | [`../integer-overflow/go/main.go`](../integer-overflow/go/main.go) | [`../integer-overflow/go/main_SECURITY.md`](../integer-overflow/go/main_SECURITY.md) |
| Race Condition (CWE-362) | [`../race-condition/go/main.go`](../race-condition/go/main.go) | [`../race-condition/go/main_SECURITY.md`](../race-condition/go/main_SECURITY.md) |

---

## 7. Quick-Reference Checklist

Use this checklist during Go code reviews. Each item maps to a vulnerability class covered in this guide.

- [ ] **Parameterized queries** — All SQL queries use `?` placeholders via `db.Query(query, args...)`, never string concatenation or `fmt.Sprintf`
- [ ] **No `sh -c` with user input** — `exec.Command` uses argument lists (`exec.Command("ping", "-c", "3", host)`), never `exec.Command("sh", "-c", userString)`
- [ ] **HTML escaping** — All user-controlled data rendered in HTML uses `html.EscapeString()` or Go's `html/template` package with autoescaping
- [ ] **No JSONP** — JSONP callbacks are validated against `^[a-zA-Z_$][a-zA-Z0-9_$]*$` or replaced with CORS
- [ ] **Authentication on every endpoint** — All sensitive handlers verify the session/token before processing
- [ ] **Server-side authorization** — Role and permission checks use server-side session data, not `c.GetHeader("X-User-Role")`
- [ ] **Object-level access control** — Resource access verifies the requesting user owns or is authorized for the specific resource
- [ ] **Minimal JSON serialization** — Response structs exclude sensitive fields; use separate response types or `json:"-"` tags
- [ ] **Strong password hashing** — Passwords are hashed with `golang.org/x/crypto/bcrypt` or `argon2` — never `crypto/md5` or `crypto/sha1`
- [ ] **Modern encryption** — AES-GCM via `crypto/aes` and `crypto/cipher` is used; no `crypto/des`, no ECB mode
- [ ] **Cryptographic randomness** — Tokens and secrets use `crypto/rand`, not `math/rand`
- [ ] **No hardcoded secrets** — API keys, passwords, DSNs, and encryption keys are loaded from environment variables or a secrets manager
- [ ] **Safe deserialization** — `encoding/gob` is not used on untrusted input; prefer `encoding/json` with size limits
- [ ] **No `plugin.Open` on untrusted files** — Go plugins are loaded only from trusted, integrity-verified sources
- [ ] **SSRF protection** — Outbound HTTP requests resolve hostnames and validate IPs against private/loopback/link-local ranges
- [ ] **Minimal error responses** — Error responses do not include `debug.Stack()`, raw `err.Error()`, DSNs, or internal paths
- [ ] **No debug mode** — `gin.SetMode(gin.ReleaseMode)` is used; no `Server` or `X-Powered-By` headers expose versions
- [ ] **Secure CORS** — `Access-Control-Allow-Origin` is set to specific trusted origins, not reflected from the request
- [ ] **Strict XML parsing** — `xml.NewDecoder` uses `Strict = true`
- [ ] **Audit logging** — Authentication events, privilege changes, financial transactions, and data exports are logged with `log.Printf`
- [ ] **No credentials in responses** — API responses do not include passwords, API keys, session tokens, or DSNs
- [ ] **Goroutine safety** — Shared mutable state uses `sync.Mutex`, `sync.RWMutex`, or `sync/atomic`; singletons use `sync.Once`
- [ ] **Nil pointer checks** — All map lookups and function returns that yield pointers are checked for `nil` before dereferencing
- [ ] **Integer overflow prevention** — Arithmetic on `int32` values is widened to `int64` before multiplication; results are not narrowed back without range checks
- [ ] **Dependency hygiene** — `go.mod` pins current versions; dependencies are checked with `govulncheck` or `nancy`
- [ ] **Race detector** — `go test -race ./...` and `go run -race` are part of the CI pipeline
