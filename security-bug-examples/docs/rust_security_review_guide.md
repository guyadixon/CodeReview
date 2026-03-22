# Rust Security Code Review Guide

## 1. Introduction

This guide provides a structured approach to security-focused code review for Rust applications. It is designed for both beginners learning to identify security vulnerabilities in Rust code and experienced developers looking for a language-specific checklist to streamline their reviews.

Rust's ownership model, borrow checker, and type system prevent entire classes of bugs — use-after-free, null pointer dereferences, and data races in safe code. However, `unsafe` blocks, third-party crate choices, and application-level logic errors still introduce serious vulnerabilities. This guide covers manual review strategies, common anti-patterns, recommended tooling, and vulnerability patterns organized by class, with cross-references to the intentionally vulnerable examples in this project.

**Audience:** Security trainees, application developers, code reviewers, and anyone evaluating Rust codebases for security weaknesses.

---

## 2. Manual Review Best Practices

### 2.1 Audit Every `unsafe` Block

Every `unsafe` block is a promise that the developer has manually verified invariants the compiler cannot check. Treat each one as a high-priority review target. Verify:
- Raw pointer dereferences stay within allocation bounds
- `ptr::read`, `ptr::write`, and `ptr::copy_nonoverlapping` use correct lengths
- Manual `Send`/`Sync` implementations are sound
- `std::alloc::alloc` and `Layout::from_size_align_unchecked` receive validated inputs

### 2.2 Trace Data from Entry to Sink

Actix-web, Rocket, and Axum accept user input through `web::Query`, `web::Json`, `web::Form`, `web::Path`, headers, and cookies. Trace every external input to where it is consumed — shell commands, HTML output, HTTP requests, or file operations. Any path from source to sink without validation is a potential vulnerability.

### 2.3 Inspect `Command::new` and Shell Invocations

Rust's `std::process::Command` is safe when used with argument lists, but passing user input through `Command::new("sh").arg("-c").arg(format!(...))` reintroduces shell injection. Flag every use of `sh -c` or `cmd /C` with `format!` string interpolation.

### 2.4 Review `format!` in HTML Contexts

Rust has no built-in HTML templating auto-escape. When Actix-web handlers build HTML responses with `format!` and user-controlled data, every interpolation point is a potential XSS vector. Check for manual escaping of `<`, `>`, `"`, `'`, and `&`.

### 2.5 Check for Hardcoded Secrets

Search for `const` or `static` string literals that look like passwords, API keys, tokens, or connection strings. Common patterns include variables named `SECRET`, `KEY`, `PASSWORD`, `TOKEN`, or connection strings containing `://user:pass@host`.

### 2.6 Evaluate Cryptographic Choices

Flag uses of the `md5` or `sha1` crates for password hashing or integrity verification. Check for the `des` crate, ECB mode encryption, or hardcoded encryption keys. Verify that session tokens use `OsRng` or `rand::thread_rng()` rather than custom PRNGs or time-based seeds.

### 2.7 Assess Access Control Logic

For every Actix-web handler, verify:
- Authentication is checked before any business logic executes
- Authorization checks use server-side session data, not client-supplied headers (e.g., `X-User-Role`)
- Object-level access control prevents users from accessing resources belonging to others (IDOR)
- `#[derive(Serialize)]` on structs does not leak sensitive fields — use `#[serde(skip_serializing)]` or separate response structs

### 2.8 Review CORS Configuration

Check `actix-cors::Cors` builder calls. The combination of `allow_any_origin()` with `supports_credentials()` effectively disables the same-origin policy. Verify that origins are restricted to specific trusted domains.

### 2.9 Examine Error Handling and `.unwrap()` Usage

Look for `.unwrap()` on `Result` or `Option` in request handlers — these cause panics that crash the server or leak stack traces. In production code, prefer `.map_err()`, `?` operator, or explicit error responses. Also check that error responses do not include internal paths, connection strings, or stack traces.

---

## 3. Common Security Pitfalls

### 3.1 Injection

| Anti-Pattern | Risk |
|---|---|
| `Command::new("sh").arg("-c").arg(format!("ping -c 3 {}", host))` | Command injection via shell interpolation |
| `format!("dig {} {} +short", record_type, domain)` passed to `sh -c` | Command injection in helper function |
| `format!("tail -n {} {} \| grep '{}'", lines, path, keyword)` via `sh -c` | Multi-parameter injection in shell pipeline |
| `format!("tar czf {} {}", archive, path)` via `sh -c` | Command injection via path parameter |
| User input rendered via `format!("<h2>{}</h2>", title)` in HTML | Stored and reflected XSS |
| `format!("{}({})", callback, json_data)` in JSONP response | XSS via callback injection |

### 3.2 Broken Access Control

| Anti-Pattern | Risk |
|---|---|
| Handler returns full struct via `HttpResponse::Ok().json(user)` with `#[derive(Serialize)]` including SSN, salary | Excessive data exposure |
| Authorization reads role from `X-User-Role` header instead of session | Client-side role spoofing |
| No ownership check on order/document access after authentication | IDOR — any authenticated user can read/modify any resource |
| Debug/config endpoints with no authentication | Information disclosure of secrets and credentials |

### 3.3 Cryptographic Failures

| Anti-Pattern | Risk |
|---|---|
| `md5::compute(password.as_bytes())` for password storage | Weak, unsalted password hashing |
| `Des::new_from_slice(&DES_KEY)` with block-by-block ECB encryption | Deprecated cipher in insecure mode |
| `const DES_KEY: [u8; 8] = *b"s3cr3t!!"` | Hardcoded encryption key |
| Custom LCG PRNG seeded with `SystemTime` nanoseconds for session tokens | Predictable token generation |
| SHA-1 hash of `format!("tkn-{}-{}", seq, timestamp)` for API tokens | Predictable inputs produce predictable tokens |

### 3.4 Insecure Design

| Anti-Pattern | Risk |
|---|---|
| Plaintext passwords stored in `HashMap` structs | No hashing at all |
| Error responses including `DB_CONNECTION` constant with embedded credentials | Credential leakage via error messages |
| Password reset token returned in API response body | Token leakage — bypasses email verification |
| `#[derive(Serialize)]` on User struct with `password` field serialized in debug endpoint | Full user record exposure |
| `const DB_CONNECTION: &str = "postgresql://user:pass@host/db"` | Hardcoded connection string with credentials |

### 3.5 Security Misconfiguration

| Anti-Pattern | Risk |
|---|---|
| `Cors::default().allow_any_origin().allow_any_method().supports_credentials()` | Overly permissive CORS disables same-origin policy |
| XML parsing without DTD rejection (defense-in-depth failure) | Latent XXE risk if XML library is swapped |
| `PUT /api/settings` with no authentication accepting arbitrary key-value pairs | Unauthenticated modification of security settings |
| Diagnostics endpoint returning `DB_HOST`, `DB_USER`, `DB_PASS` | Credential exposure via admin endpoint |
| `std::env::vars()` collected and returned in JSON response | All environment variables exposed |
| Hardcoded `ADMIN_TOKEN` constant for admin endpoint protection | Static credential in source code |

### 3.6 Vulnerable Components

| Anti-Pattern | Risk |
|---|---|
| Pinning actix-web to 3.x when 4.x is current | Outdated framework with known issues |
| Pinning serde/serde_json to significantly old versions | Missing security patches and hardening |
| Not running `cargo audit` in CI | Known CVEs in dependencies go undetected |

### 3.7 Auth Failures

| Anti-Pattern | Risk |
|---|---|
| `const ADMIN_BOOTSTRAP_KEY: &str = "abk_prod_2024_f8e7d6c5"` | Hardcoded admin credential |
| `const INTER_SERVICE_TOKEN: &str = "ist-mesh-auth-prod-2024"` | Hardcoded service-to-service token |
| No rate limiting on login endpoint | Unrestricted brute-force attacks |
| Reset token returned in API response instead of sent via email | Account takeover via token leakage |
| MD5 for password hashing in authentication flow | Weak hash easily reversed |

### 3.8 Logging and Monitoring Failures

| Anti-Pattern | Risk |
|---|---|
| No `log` crate imported, no logging macros in authentication handlers | Failed logins go undetected |
| Successful login returns password and API key in response with no audit log | Credential leakage and invisible account takeover |
| Role changes performed without audit logging | Silent privilege escalation |
| Financial transactions processed without persistent logging | Fraud goes undetected |
| Data export endpoint with no logging of who requested the export | Mass exfiltration invisible |

### 3.9 SSRF

| Anti-Pattern | Risk |
|---|---|
| `reqwest::get(&body.url)` without any URL validation | Unrestricted SSRF |
| Blocklist checking only `localhost` and `127.0.0.1` (missing `[::1]`, `169.254.x.x`, private ranges) | SSRF blocklist bypass |
| Webhook callback URL validated at registration but not re-validated at delivery | Two-step SSRF |
| Hostname string check for `169.254` without DNS resolution (DNS rebinding bypass) | Metadata endpoint access via DNS rebinding |
| Service proxy with fallback to user-supplied `base_url` | Open relay to internal services |

### 3.10 Memory Safety (unsafe)

| Anti-Pattern | Risk |
|---|---|
| `for i in 0..=len` with `ptr::write(ptr.add(i), ...)` | Off-by-one out-of-bounds write |
| `ptr::copy_nonoverlapping(src, dest, name.len())` into fixed-size array without length check | Heap buffer overflow |
| `let total_len: u16 = parts.iter().map(\|s\| s.len() as u16).sum()` for allocation size | Integer truncation causes undersized allocation |
| `Layout::from_size_align_unchecked` with attacker-controlled sizes | Undefined behavior from invalid layout |
| `unsafe impl Send for UnsafeSendCell<T> {}` / `unsafe impl Sync` | Bypasses borrow checker, enables data races |

### 3.11 Race Conditions

| Anti-Pattern | Risk |
|---|---|
| Read-yield-write on shared data through `UnsafeCell` without synchronization | Lost updates, balance corruption |
| Check-then-act (`if available > 0` then yield then decrement) through unsafe cell | TOCTOU — overselling, double-spend |
| `static mut` flag-guarded singleton initialization without synchronization | Multiple initializations, data loss |
| Non-atomic counter increment through unsafe shared access | Lost counter updates |

---

## 4. Recommended SAST Tools & Linters

### 4.1 cargo-audit

cargo-audit checks `Cargo.lock` for crates with known security vulnerabilities reported to the RustSec Advisory Database.

**Installation:**

```bash
cargo install cargo-audit
```

**Basic usage — audit the current project:**

```bash
cargo audit
```

**Generate a JSON report:**

```bash
cargo audit --json
```

**Check a specific Cargo.lock file:**

```bash
cargo audit -f /path/to/Cargo.lock
```

**What cargo-audit catches:** Known CVEs in dependencies, unmaintained crates, yanked crate versions, and advisories from the RustSec database. It is particularly effective at detecting outdated frameworks (e.g., actix-web 3.x) and crates with published security advisories.

### 4.2 clippy

Clippy is the official Rust linter, included with rustup. It provides hundreds of lint checks including several security-relevant ones.

**Installation (included with rustup):**

```bash
rustup component add clippy
```

**Basic usage — lint the current project:**

```bash
cargo clippy
```

**Treat all warnings as errors:**

```bash
cargo clippy -- -D warnings
```

**Run with all lint groups enabled:**

```bash
cargo clippy -- -W clippy::all -W clippy::pedantic -W clippy::nursery
```

**Lint a specific file (via project):**

```bash
cargo clippy -p my_crate
```

**What clippy catches:** Unnecessary `unsafe` blocks, `.unwrap()` on `Result`/`Option` in library code, suspicious arithmetic (integer overflow patterns), redundant clones, missing error handling, `as` casts that may truncate, and many idiomatic Rust issues. Security-relevant lints include `clippy::unwrap_used`, `clippy::expect_used`, `clippy::cast_possible_truncation`, and `clippy::transmute_ptr_to_ref`.

### 4.3 Semgrep

Semgrep is a multi-language static analysis tool with pattern-based rules. It supports Rust and has community rules for common vulnerability patterns.

**Installation:**

```bash
pip install semgrep
# or
brew install semgrep
```

**Scan with the default Rust security ruleset:**

```bash
semgrep --config "p/rust" security-bug-examples/
```

**Scan with OWASP Top 10 rules:**

```bash
semgrep --config "p/owasp-top-ten" security-bug-examples/
```

**Scan a single file:**

```bash
semgrep --config "p/rust" injection/command-injection/rust/main.rs
```

**Run with auto configuration (recommended for first-time scans):**

```bash
semgrep --config auto security-bug-examples/
```

**What Semgrep catches:** Command injection via `Command::new("sh").arg("-c")` with format strings, hardcoded credentials, use of weak cryptographic crates (`md5`, `des`), `unsafe` block patterns, and framework-specific misconfigurations. Semgrep's pattern matching is effective at detecting string-formatting-based injection in Rust that clippy does not flag.

---

## 5. Language-Specific Vulnerability Patterns

### 5.1 Command Injection (CWE-78)

**Pattern: Shell execution via `Command::new("sh").arg("-c")` with `format!`**

```rust
// Vulnerable — user input interpolated into shell command
let cmd = format!("ping -c 3 {}", host);
Command::new("sh").arg("-c").arg(&cmd).output();
```

**Pattern: Helper function with shell command construction**

```rust
// Vulnerable — domain parameter passed through without sanitization
fn run_dig(domain: &str, record_type: &str) -> String {
    let cmd = format!("dig {} {} +short", record_type, domain);
    Command::new("sh").arg("-c").arg(&cmd).output()
    // ...
}
```

**Pattern: Multi-parameter shell pipeline**

```rust
// Vulnerable — three user-controlled parameters in a pipeline
let cmd = format!("tail -n {} {} | grep '{}'", lines, log_path, keyword);
Command::new("sh").arg("-c").arg(&cmd).output();
```

**Safe alternative:**

```rust
// Use argument list — no shell interpretation
Command::new("ping").args(["-c", "3", &host]).output();
```

### 5.2 Cross-Site Scripting — XSS (CWE-79)

**Pattern: Stored XSS via `format!` in HTML**

```rust
// Vulnerable — post content rendered without escaping
page.push_str(&format!("<h2>{}</h2>", post.title));
page.push_str(&format!("<div>{}</div>", post.content));
```

**Pattern: Reflected XSS in search results**

```rust
// Vulnerable — query reflected back into page
page.push_str(&format!("<h2>Results for: {}</h2>", q));
```

**Pattern: XSS via `href` attribute (javascript: protocol)**

```rust
// Vulnerable — website URL injected into href without validation
page.push_str(&format!("<a href='{}'>{}</a>", profile.website, profile.website));
```

**Pattern: JSONP callback injection**

```rust
// Vulnerable — callback parameter not validated
HttpResponse::Ok()
    .content_type("application/javascript")
    .body(format!("{}({})", cb, json_data));
```

**Safe alternative:**

```rust
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#x27;")
}
page.push_str(&format!("<h2>{}</h2>", escape_html(&post.title)));
```

### 5.3 Broken Access Control (CWE-200, CWE-284, CWE-639)

**Pattern: No authentication on sensitive endpoint**

```rust
async fn get_user_profile(path: web::Path<u32>, state: web::Data<AppState>) -> HttpResponse {
    let users = state.users.lock().unwrap();
    match users.get(&user_id) {
        Some(user) => HttpResponse::Ok().json(user), // Returns SSN, salary — no auth
        None => HttpResponse::NotFound().json(json!({"error": "Not found"})),
    }
}
```

**Pattern: Client-controlled authorization header**

```rust
let client_role = req.headers()
    .get("X-User-Role")
    .and_then(|v| v.to_str().ok())
    .unwrap_or("");
if client_role != "admin" {
    return HttpResponse::Forbidden().json(json!({"error": "Admin access required"}));
}
```

**Pattern: Missing object-level authorization (IDOR)**

```rust
// Authenticated but no ownership check — any user can access any order
let order = orders.get(&order_id);
HttpResponse::Ok().json(order)
```

### 5.4 Cryptographic Failures (CWE-327, CWE-328, CWE-330)

**Pattern: MD5 for password hashing**

```rust
fn compute_md5(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}
// Used for: user.password_hash = compute_md5(&password);
```

**Pattern: DES in ECB mode with hardcoded key**

```rust
const DES_KEY: [u8; 8] = *b"s3cr3t!!";
// Block-by-block encryption without chaining
let cipher = Des::new_from_slice(&DES_KEY).unwrap();
for chunk in encrypted.chunks_mut(8) {
    cipher.encrypt_block(block);
}
```

**Pattern: Custom LCG PRNG for session tokens**

```rust
fn simple_prng_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state >> 33
}
// Seeded with SystemTime nanoseconds — predictable
```

**Safe alternative:**

```rust
use bcrypt::{hash, verify, DEFAULT_COST};
let hashed = hash(password, DEFAULT_COST).unwrap();

use rand::Rng;
let token: String = rand::thread_rng()
    .sample_iter(&rand::distributions::Alphanumeric)
    .take(32)
    .map(char::from)
    .collect();
```

### 5.5 Insecure Design (CWE-209, CWE-522)

**Pattern: Plaintext password storage**

```rust
m.insert(1, User {
    id: 1, username: "admin".into(),
    password: "Adm1n_Pr0d!".into(), // Plaintext — no hashing
    // ...
});
```

**Pattern: Verbose error responses leaking credentials**

```rust
HttpResponse::InternalServerError().json(serde_json::json!({
    "error": "Report generation failed",
    "details": e,
    "connection_string": DB_CONNECTION  // Contains password
}))
```

**Pattern: User enumeration via distinct error messages**

```rust
// Different responses reveal whether username exists
HttpResponse::NotFound().json(json!({"error": format!("No account found for '{}'", username)}))
// vs.
HttpResponse::Unauthorized().json(json!({"error": "Incorrect password", "attempts": count}))
```

### 5.6 Security Misconfiguration (CWE-16, CWE-611)

**Pattern: Overly permissive CORS with credentials**

```rust
let cors = Cors::default()
    .allow_any_origin()
    .allow_any_method()
    .allow_any_header()
    .supports_credentials();
```

**Pattern: Unauthenticated settings modification**

```rust
// No auth check — anyone can disable TLS verification, rate limiting
async fn update_settings(body: web::Json<HashMap<String, Value>>, state: web::Data<AppState>) -> HttpResponse {
    let mut settings = state.settings.lock().unwrap();
    for (k, v) in body.into_inner() {
        settings.insert(k, v);
    }
    // ...
}
```

**Pattern: Environment variables dumped to response**

```rust
let env_vars: HashMap<String, String> = std::env::vars().collect();
HttpResponse::Ok().json(json!({"env": env_vars}))
```

### 5.7 Vulnerable and Outdated Components (CWE-1104)

**Pattern: Outdated framework version in Cargo.toml**

```toml
[dependencies]
actix-web = "3.3.3"  # Major version behind, unmaintained
serde = "1.0.130"    # Significantly outdated
serde_json = "1.0.68" # Missing parsing fixes
```

**Safe alternative:**

```toml
[dependencies]
actix-web = "4.4.0"
serde = { version = "1.0.193", features = ["derive"] }
serde_json = "1.0.108"
```

### 5.8 Auth Failures (CWE-287, CWE-307, CWE-798)

**Pattern: Hardcoded credentials as constants**

```rust
const ADMIN_BOOTSTRAP_KEY: &str = "abk_prod_2024_f8e7d6c5";
const INTER_SERVICE_TOKEN: &str = "ist-mesh-auth-prod-2024";
```

**Pattern: No rate limiting on login**

```rust
// Login handler processes unlimited attempts — no throttling or lockout
async fn login(body: web::Json<LoginRequest>, state: web::Data<AppState>) -> HttpResponse {
    // ... direct credential check with no rate limit
}
```

**Pattern: Reset token returned in response**

```rust
HttpResponse::Ok().json(json!({
    "message": "Reset email sent",
    "token": token,  // Should only be sent via email
}))
```

### 5.9 Logging and Monitoring Failures (CWE-778)

**Pattern: No logging crate imported, no audit trail**

```rust
// Entire application has no `use log::*;` or logging macro calls
// Failed logins, role changes, data exports — all silent
```

**Pattern: Credentials in API responses**

```rust
HttpResponse::Ok().json(json!({
    "token": token,
    "password": user.password,   // Plaintext password in response
    "api_key": user.api_key,     // API key in response
}))
```

### 5.10 SSRF (CWE-918)

**Pattern: Unrestricted URL fetch**

```rust
let resp = reqwest::get(&body.url).await?;
// No validation of URL destination
```

**Pattern: Incomplete blocklist**

```rust
let blocked = ["localhost", "127.0.0.1"];
// Missing: [::1], 0.0.0.0, 169.254.x.x, 10.x.x.x, 172.16.x.x, 192.168.x.x
```

**Pattern: Service proxy with user-controlled fallback**

```rust
let base = match service_map.get(service) {
    Some(url) => url.to_string(),
    None => query.base_url.clone(), // Attacker-controlled fallback
};
let full_url = format!("{}{}", base, path);
reqwest::get(&full_url).await?;
```

**Safe alternative:**

```rust
use std::net::ToSocketAddrs;
if let Some(host) = parsed.host_str() {
    if let Ok(addrs) = (host, 0).to_socket_addrs() {
        for addr in addrs {
            if addr.ip().is_loopback() || addr.ip().is_private() {
                return HttpResponse::Forbidden().json(json!({"error": "Blocked"}));
            }
        }
    }
}
```

### 5.11 Out-of-bounds Write (CWE-787)

**Pattern: Off-by-one with inclusive range in unsafe pointer arithmetic**

```rust
unsafe {
    let ptr = data.as_mut_ptr();
    let len = data.len();
    for i in 0..=len {  // BUG: should be 0..len
        let val = ptr::read(ptr.add(i));
        ptr::write(ptr.add(i), val * factor);
    }
}
```

**Pattern: Unbounded copy into fixed-size buffer**

```rust
unsafe {
    let dest = self.names[idx].as_mut_ptr();
    let src = name.as_ptr();
    let len = name.len();  // Not clamped to buffer size
    ptr::copy_nonoverlapping(src, dest, len);
}
```

**Pattern: Integer truncation in allocation size**

```rust
// u16 wraps around for combined lengths > 65535
let total_len: u16 = parts.iter().map(|s| s.len() as u16).sum();
let layout = Layout::from_size_align_unchecked(total_len as usize, 1);
let buf = alloc(layout);
// Copy loop writes full data into undersized buffer
```

**Safe alternative:**

```rust
// Avoid unsafe entirely for common operations
fn scale_buffer(data: &mut [f64], factor: f64) {
    for val in data.iter_mut() {
        *val *= factor;
    }
}
```

### 5.12 Race Conditions (CWE-362)

**Pattern: Unsafe Send/Sync wrapper bypassing borrow checker**

```rust
struct UnsafeSendCell<T>(UnsafeCell<T>);
unsafe impl<T> Send for UnsafeSendCell<T> {}
unsafe impl<T> Sync for UnsafeSendCell<T> {}
// Enables data races the compiler would otherwise prevent
```

**Pattern: Check-then-act without synchronization**

```rust
unsafe {
    let pool = &mut *cell.get();
    if pool.available > 0 {
        thread::yield_now();  // Window for race
        pool.available -= 1;
        pool.sold += 1;
    }
}
```

**Pattern: `static mut` singleton initialization race**

```rust
static mut CONFIG_INITIALIZED: bool = false;
static mut GLOBAL_CONFIG: Option<Vec<(String, String)>> = None;

unsafe fn get_global_config() -> &'static mut Vec<(String, String)> {
    if !CONFIG_INITIALIZED {
        thread::yield_now();  // Multiple threads pass the check
        GLOBAL_CONFIG = Some(Vec::new());
        CONFIG_INITIALIZED = true;
    }
    GLOBAL_CONFIG.as_mut().unwrap()
}
```

**Safe alternative:**

```rust
use std::sync::{Arc, Mutex, OnceLock};

// For shared mutable state
let account = Arc::new(Mutex::new(BankAccount::new("Shared", 10000)));

// For lazy singleton initialization (Rust 1.70+)
static GLOBAL_CONFIG: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();
fn get_global_config() -> &'static Mutex<Vec<(String, String)>> {
    GLOBAL_CONFIG.get_or_init(|| Mutex::new(Vec::new()))
}
```

---

## 6. Cross-References to Examples

The table below maps each vulnerability class to the Rust source file and companion documentation in this project. All paths are relative to the `docs/` directory.

| Vulnerability Class | Source File | Companion Doc |
|---|---|---|
| Command Injection (CWE-78) | [`../injection/command-injection/rust/main.rs`](../injection/command-injection/rust/main.rs) | [`../injection/command-injection/rust/main_SECURITY.md`](../injection/command-injection/rust/main_SECURITY.md) |
| Cross-Site Scripting (CWE-79) | [`../injection/xss/rust/main.rs`](../injection/xss/rust/main.rs) | [`../injection/xss/rust/main_SECURITY.md`](../injection/xss/rust/main_SECURITY.md) |
| Broken Access Control (CWE-200, CWE-284, CWE-639) | [`../broken-access-control/rust/main.rs`](../broken-access-control/rust/main.rs) | [`../broken-access-control/rust/main_SECURITY.md`](../broken-access-control/rust/main_SECURITY.md) |
| Cryptographic Failures (CWE-327, CWE-328, CWE-330) | [`../cryptographic-failures/rust/main.rs`](../cryptographic-failures/rust/main.rs) | [`../cryptographic-failures/rust/main_SECURITY.md`](../cryptographic-failures/rust/main_SECURITY.md) |
| Insecure Design (CWE-209, CWE-522) | [`../insecure-design/rust/main.rs`](../insecure-design/rust/main.rs) | [`../insecure-design/rust/main_SECURITY.md`](../insecure-design/rust/main_SECURITY.md) |
| Security Misconfiguration (CWE-16, CWE-611) | [`../security-misconfiguration/rust/main.rs`](../security-misconfiguration/rust/main.rs) | [`../security-misconfiguration/rust/main_SECURITY.md`](../security-misconfiguration/rust/main_SECURITY.md) |
| Vulnerable Components (CWE-1104) | [`../vulnerable-components/rust/main.rs`](../vulnerable-components/rust/main.rs) | [`../vulnerable-components/rust/main_SECURITY.md`](../vulnerable-components/rust/main_SECURITY.md) |
| Auth Failures (CWE-287, CWE-307, CWE-798) | [`../auth-failures/rust/main.rs`](../auth-failures/rust/main.rs) | [`../auth-failures/rust/main_SECURITY.md`](../auth-failures/rust/main_SECURITY.md) |
| Logging/Monitoring Failures (CWE-778) | [`../logging-monitoring-failures/rust/main.rs`](../logging-monitoring-failures/rust/main.rs) | [`../logging-monitoring-failures/rust/main_SECURITY.md`](../logging-monitoring-failures/rust/main_SECURITY.md) |
| SSRF (CWE-918) | [`../ssrf/rust/main.rs`](../ssrf/rust/main.rs) | [`../ssrf/rust/main_SECURITY.md`](../ssrf/rust/main_SECURITY.md) |
| Out-of-bounds Write (CWE-787) | [`../memory-safety/out-of-bounds-write/rust/main.rs`](../memory-safety/out-of-bounds-write/rust/main.rs) | [`../memory-safety/out-of-bounds-write/rust/main_SECURITY.md`](../memory-safety/out-of-bounds-write/rust/main_SECURITY.md) |
| Race Condition (CWE-362) | [`../race-condition/rust/main.rs`](../race-condition/rust/main.rs) | [`../race-condition/rust/main_SECURITY.md`](../race-condition/rust/main_SECURITY.md) |

**Note:** Rust is excluded from SQL Injection (type system makes raw SQL uncommon), Integrity Failures (serde is safe by default), Use After Free (ownership system prevents it), NULL Pointer Dereference (no null in safe Rust), and Integer Overflow (checked in debug, wrapping in release — covered separately in the integer-overflow category for Rust).

---

## 7. Quick-Reference Checklist

Use this checklist during Rust code reviews. Each item maps to a vulnerability class covered in this guide.

- [ ] **`unsafe` audit** — Every `unsafe` block is justified, minimally scoped, and its invariants are documented and verified (bounds checks, valid pointers, correct lifetimes)
- [ ] **No shell injection** — `Command::new("sh").arg("-c")` is never used with `format!` containing user input; use argument lists instead
- [ ] **Output encoding** — All user-controlled data rendered in HTML responses is escaped (`<`, `>`, `"`, `&`); consider using a templating engine with auto-escaping
- [ ] **Authentication on every endpoint** — All sensitive handlers verify the session/token before processing
- [ ] **Server-side authorization** — Role and permission checks use server-side session data, not client-supplied headers
- [ ] **Object-level access control** — Resource access verifies the requesting user owns or is authorized for the specific resource
- [ ] **No sensitive fields in responses** — `#[derive(Serialize)]` structs returned in responses do not include passwords, SSNs, or API keys; use `#[serde(skip_serializing)]` or separate response structs
- [ ] **Strong password hashing** — Passwords are hashed with `bcrypt`, `argon2`, or `scrypt` — never `md5` or `sha1`
- [ ] **Modern encryption** — AES-GCM via the `aes-gcm` crate is used; no `des` crate, no ECB mode
- [ ] **Cryptographic randomness** — Tokens and secrets use `rand::thread_rng()` with `OsRng` or the `getrandom` crate, not custom PRNGs or time-based seeds
- [ ] **No hardcoded secrets** — API keys, passwords, encryption keys, and connection strings are loaded from environment variables or a secrets manager, not `const` or `static` literals
- [ ] **SSRF protection** — Outbound HTTP requests via `reqwest` validate URLs against an allowlist; resolve hostnames and block private/loopback/metadata IPs before fetching
- [ ] **Minimal error responses** — Error responses do not include stack traces, database connection strings, or internal configuration
- [ ] **Secure CORS** — `actix-cors::Cors` is configured with specific trusted origins, not `allow_any_origin()` combined with `supports_credentials()`
- [ ] **XML safety** — XML parsers reject DTD declarations; if using libraries other than `roxmltree`, explicitly disable entity resolution
- [ ] **Audit logging** — Authentication events, privilege changes, financial transactions, and data exports are logged using the `log` or `tracing` crate
- [ ] **No credentials in responses** — API responses do not include passwords, API keys, or other secrets
- [ ] **Thread safety** — Shared mutable state uses `Arc<Mutex<T>>`, `RwLock`, or atomics; no `unsafe impl Sync` on `UnsafeCell` wrappers; no `static mut` for shared state
- [ ] **Safe pointer arithmetic** — `unsafe` pointer operations use exclusive ranges (`0..len`, not `0..=len`); copy lengths are clamped to destination buffer sizes
- [ ] **No integer truncation in allocations** — Allocation sizes use `usize`, not `u16` or `u32`; `as` casts are checked for truncation
- [ ] **Dependency hygiene** — `Cargo.toml` pins reasonable versions; `cargo audit` runs in CI; outdated major versions are upgraded
- [ ] **Rate limiting** — Authentication endpoints use middleware like `actix-governor` to throttle brute-force attempts
