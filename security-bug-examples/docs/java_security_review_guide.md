# Java Security Code Review Guide

## 1. Introduction

This guide provides a structured approach to security-focused code review for Java applications. It is designed for both beginners learning to identify security vulnerabilities in Java code and experienced developers looking for a language-specific checklist to streamline their reviews.

Java's strong type system, managed memory, and mature ecosystem offer many safety guarantees — but the language and its frameworks still expose developers to a wide range of security pitfalls including injection, deserialization, reflection abuse, JNDI injection, and misconfigured XML parsers. This guide covers manual review strategies, common anti-patterns, recommended tooling, and vulnerability patterns organized by class, with cross-references to the intentionally vulnerable examples in this project.

**Audience:** Security trainees, application developers, code reviewers, and anyone evaluating Java codebases for security weaknesses.

---

## 2. Manual Review Best Practices

### 2.1 Trace Data from Entry to Sink

Spring Boot applications accept user input through `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, and `HttpServletRequest` methods. Trace every external input to where it is consumed — JDBC queries, `Runtime.exec()` calls, file operations, HTTP clients, or rendered HTML. Any path from source to sink without validation or sanitization is a potential vulnerability.

### 2.2 Inspect String Concatenation in Sensitive Contexts

Java offers string concatenation (`+`), `String.format()`, `StringBuilder`, and template expressions. When any of these are used to build SQL queries, shell commands, HTML output, LDAP queries, or URLs with user-controlled data, treat it as a high-priority finding.

### 2.3 Review Import Statements

Scan imports for classes known to introduce risk:
- `java.io.ObjectInputStream` — deserialization of untrusted data
- `java.lang.Runtime`, `java.lang.ProcessBuilder` — command injection
- `javax.script.ScriptEngine` — arbitrary code execution
- `javax.naming.InitialContext`, `javax.naming.Context` — JNDI injection
- `java.lang.reflect.*` — reflection abuse, access control bypass
- `javax.xml.parsers.*`, `org.xml.sax.*` without secure configuration — XXE attacks
- `java.sql.Statement` (vs. `PreparedStatement`) — SQL injection
- `javax.crypto.Cipher` with `"DES"` or `"/ECB/"` — weak cryptography

### 2.4 Check for Hardcoded Secrets

Search for string literals that look like passwords, API keys, tokens, or connection strings. Common patterns include fields named `SECRET_KEY`, `API_KEY`, `PASSWORD`, `TOKEN`, `MASTER_KEY`, or JDBC URLs containing credentials like `jdbc:mysql://user:pass@host`.

### 2.5 Examine Error Handling

Look for catch blocks that expose stack traces, internal paths, or database details to the caller. In Spring Boot, check for `@ExceptionHandler` methods that return `e.getMessage()`, `e.getStackTrace()`, or raw exception objects. Watch for `@ResponseStatus` annotations that may leak internal error details.

### 2.6 Evaluate Cryptographic Choices

Flag uses of `MessageDigest.getInstance("MD5")` or `"SHA-1"` for password hashing or integrity verification. Check for `Cipher.getInstance("DES/ECB/PKCS5Padding")` or any ECB mode usage. Verify that `java.util.Random` (not `java.security.SecureRandom`) is not used for security-sensitive token generation. Look for hardcoded encryption keys stored as `byte[]` or `String` literals.

### 2.7 Assess Access Control Logic

For every endpoint, verify:
- Authentication is checked before any business logic executes (Spring Security filters, `@PreAuthorize`, or manual checks)
- Authorization checks use server-side session data, not client-supplied headers (e.g., `X-User-Role`)
- Object-level access control prevents users from accessing resources belonging to others (IDOR)
- Method-level security annotations (`@Secured`, `@RolesAllowed`) are applied consistently

### 2.8 Review Configuration Defaults

Check `application.properties` / `application.yml` for verbose error exposure (`server.error.include-stacktrace=always`), permissive CORS (`@CrossOrigin(origins = "*")`), disabled CSRF protection, exposed actuator endpoints, and debug-level logging in production.

---

## 3. Common Security Pitfalls

### 3.1 Injection

| Anti-Pattern | Risk |
|---|---|
| `"SELECT * FROM t WHERE x = '" + userInput + "'"` with `Statement.executeQuery()` | SQL injection via string concatenation |
| `String.format("SELECT ... WHERE id = %s", id)` passed to `Statement` | SQL injection via format string |
| `Runtime.getRuntime().exec("ping " + host)` | Command injection via `Runtime.exec()` |
| `new ProcessBuilder("sh", "-c", "nslookup " + domain).start()` | Command injection via shell invocation |
| User input rendered directly into HTML string without escaping | Stored and reflected XSS |
| JSONP callback parameter used without sanitization | XSS via callback injection |

### 3.2 Broken Access Control

| Anti-Pattern | Risk |
|---|---|
| Endpoint returns full user object (including SSN, salary) without field filtering | Excessive data exposure |
| Authorization check reads role from `X-User-Role` header instead of session/token | Client-side role spoofing |
| No ownership check on resource access/update — any authenticated user can read/modify any record | IDOR vulnerability |
| Actuator or admin endpoints exposed without authentication | Information disclosure of secrets and configuration |

### 3.3 Cryptographic Failures

| Anti-Pattern | Risk |
|---|---|
| `MessageDigest.getInstance("MD5")` for password storage | Weak, unsalted password hashing |
| `Cipher.getInstance("DES/ECB/PKCS5Padding")` | Deprecated cipher in insecure mode |
| `new Random()` or `new Random(System.currentTimeMillis())` for token generation | Predictable PRNG seeding |
| `private static final String MASTER_KEY = "s3cr3tK3y!!"` | Key exposure in source code |

### 3.4 Insecure Design

| Anti-Pattern | Risk |
|---|---|
| Plaintext passwords stored in `HashMap` or configuration | No hashing at all |
| Error responses revealing usernames, email existence, or attempt counts | User enumeration |
| Password reset tokens returned in API response body | Token leakage |
| `e.getStackTrace()` or `e.getMessage()` returned to client in JSON | Stack trace information disclosure |

### 3.5 Security Misconfiguration

| Anti-Pattern | Risk |
|---|---|
| `server.error.include-stacktrace=always` in application.properties | Stack traces exposed to clients |
| `@CrossOrigin(origins = "*")` or reflecting any `Origin` header | Overly permissive CORS |
| `DocumentBuilderFactory` without disabling external entities | XXE via XML entity resolution |
| `SAXParserFactory` without `FEATURE_SECURE_PROCESSING` | XXE and billion-laughs attacks |
| `Server` header exposing framework and Java version | Technology fingerprinting |

### 3.6 Vulnerable Components

| Anti-Pattern | Risk |
|---|---|
| Outdated Spring Boot version with known CVEs in `pom.xml` | Known vulnerabilities in framework |
| Using `SnakeYAML` `Yaml.load()` without `SafeConstructor` | YAML deserialization to arbitrary objects |
| Outdated Jackson or Gson with known deserialization CVEs | Remote code execution via polymorphic deserialization |
| Log4j versions vulnerable to Log4Shell (CVE-2021-44228) | Remote code execution via JNDI lookup |

### 3.7 Integrity Failures (Deserialization)

| Anti-Pattern | Risk |
|---|---|
| `new ObjectInputStream(untrustedStream).readObject()` | Arbitrary code execution via Java deserialization |
| `Yaml.load(untrustedInput)` with default constructor | Arbitrary object instantiation via YAML |
| `XMLDecoder` on untrusted XML input | Remote code execution |
| Accepting serialized objects from HTTP request bodies without validation | Deserialization gadget chain attacks |

### 3.8 Authentication Failures

| Anti-Pattern | Risk |
|---|---|
| Hardcoded credentials: `if (password.equals("admin123"))` | Credential exposure in source code |
| No rate limiting on login endpoint | Brute-force attacks |
| JWT secret stored as string literal | Token forgery if secret is leaked |
| `password.equals(storedPassword)` with plaintext comparison | Timing attack and no hashing |

### 3.9 Logging and Monitoring Failures

| Anti-Pattern | Risk |
|---|---|
| Login response includes `password` and `apiKey` fields | Credential leakage in responses |
| No logging of failed authentication attempts | Brute-force attacks go undetected |
| No logging of privilege changes (role updates, deactivations) | Unauthorized changes are invisible |
| Bulk operations with no audit trail | Mass data exfiltration undetected |
| Data export endpoint returns raw passwords | Sensitive data in export payloads |

### 3.10 SSRF

| Anti-Pattern | Risk |
|---|---|
| `new URL(userUrl).openStream()` without allowlist | Unrestricted SSRF |
| Blocklist checking only `localhost` and `127.0.0.1` (missing `0.0.0.0`, `[::1]`, decimal IPs) | SSRF blocklist bypass |
| Proxy endpoint accepting arbitrary `baseUrl` parameter | Open proxy to internal services |
| Webhook callback URLs not validated against internal ranges | SSRF via webhook registration |

### 3.11 Race Conditions

| Anti-Pattern | Risk |
|---|---|
| Check-then-act on `this.balance` without `synchronized` | Double-spend / negative balance |
| `checkAvailability()` then `reserve()` without atomicity | Overselling tickets |
| Read-modify-write on shared `HashMap` without synchronization | Lost updates, corrupted state |
| Singleton with `Thread.sleep` in constructor and no `synchronized` | Multiple singleton instances |

---

## 4. Recommended SAST Tools & Linters

### 4.1 SpotBugs

SpotBugs is a static analysis tool for Java that finds bug patterns in bytecode. With the Find Security Bugs plugin, it detects a wide range of security vulnerabilities.

**Installation (standalone):**

```bash
# Download SpotBugs
wget https://github.com/spotbugs/spotbugs/releases/download/4.8.3/spotbugs-4.8.3.tgz
tar xzf spotbugs-4.8.3.tgz
export PATH=$PATH:$(pwd)/spotbugs-4.8.3/bin
```

**Installation (Maven plugin — recommended):**

Add to your `pom.xml`:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.github.spotbugs</groupId>
      <artifactId>spotbugs-maven-plugin</artifactId>
      <version>4.8.3.1</version>
      <configuration>
        <plugins>
          <plugin>
            <groupId>com.h3xstream.findsecbugs</groupId>
            <artifactId>findsecbugs-plugin</artifactId>
            <version>1.13.0</version>
          </plugin>
        </plugins>
      </configuration>
    </plugin>
  </plugins>
</build>
```

**Basic usage — run via Maven:**

```bash
mvn spotbugs:check
```

**Generate an HTML report:**

```bash
mvn spotbugs:spotbugs
# Report at target/spotbugsXml.xml; use spotbugs:gui to view interactively
```

**Scan a single compiled class directory:**

```bash
spotbugs -textui -effort:max -low target/classes/
```

**What SpotBugs + Find Security Bugs catches:** SQL injection, command injection, XSS, path traversal, XXE, LDAP injection, insecure deserialization (`ObjectInputStream`), weak cryptography (MD5, SHA-1, DES, ECB), hardcoded passwords, predictable `Random` usage, SSRF patterns, unvalidated redirects, and Spring-specific security issues.

### 4.2 PMD

PMD is a source code analyzer that finds common programming flaws including security issues. It works on source code (no compilation required) and supports custom rule sets.

**Installation:**

```bash
# Download PMD
wget https://github.com/pmd/pmd/releases/download/pmd_releases%2F7.0.0/pmd-dist-7.0.0-bin.zip
unzip pmd-dist-7.0.0-bin.zip
export PATH=$PATH:$(pwd)/pmd-bin-7.0.0/bin
```

**Installation (Maven plugin):**

```xml
<build>
  <plugins>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-pmd-plugin</artifactId>
      <version>3.21.2</version>
      <configuration>
        <rulesets>
          <ruleset>category/java/security.xml</ruleset>
          <ruleset>category/java/errorprone.xml</ruleset>
        </rulesets>
      </configuration>
    </plugin>
  </plugins>
</build>
```

**Basic usage — scan a single file:**

```bash
pmd check -d injection/sql-injection/java/App.java -R category/java/security.xml -f text
```

**Scan a directory with multiple rule sets:**

```bash
pmd check -d security-bug-examples/ -R category/java/security.xml,category/java/errorprone.xml -f text
```

**Run via Maven:**

```bash
mvn pmd:check
```

**What PMD catches:** Hardcoded cryptographic keys, insecure `Random` usage, empty catch blocks that swallow security exceptions, overly broad exception handling, unused security-related imports, and code style issues that may mask vulnerabilities. PMD's security ruleset is smaller than SpotBugs but complements it well for source-level analysis.

### 4.3 Semgrep

Semgrep is a multi-language static analysis tool with pattern-based rules. It supports custom rules and has a large community rule registry with extensive Java coverage.

**Installation:**

```bash
pip install semgrep
# or
brew install semgrep
```

**Scan with the default Java security ruleset:**

```bash
semgrep --config "p/java" security-bug-examples/
```

**Scan with OWASP Top 10 rules:**

```bash
semgrep --config "p/owasp-top-ten" security-bug-examples/
```

**Scan a single file:**

```bash
semgrep --config "p/java" injection/sql-injection/java/App.java
```

**Run with auto configuration (recommended for first-time scans):**

```bash
semgrep --config auto security-bug-examples/
```

**What Semgrep catches:** SQL injection via `Statement` (vs. `PreparedStatement`), command injection via `Runtime.exec()` and `ProcessBuilder`, XSS in Spring MVC responses, insecure deserialization (`ObjectInputStream`), XXE via unconfigured XML parsers, SSRF patterns, hardcoded secrets, weak cryptography, JNDI injection, and many Spring Boot-specific issues. Semgrep's pattern matching is particularly effective at detecting framework-specific anti-patterns that bytecode-based tools may miss.

---

## 5. Language-Specific Vulnerability Patterns

### 5.1 SQL Injection (CWE-89)

**Pattern: String concatenation with `Statement`**

```java
// Vulnerable — user input concatenated directly into SQL
String query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'";
ResultSet rs = connection.createStatement().executeQuery(query);
```

**Pattern: `String.format()` in query construction**

```java
// Vulnerable — format string builds WHERE clause from user input
String query = String.format("SELECT * FROM users WHERE id = %s", userId);
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Pattern: Unvalidated ORDER BY injection**

```java
// Vulnerable — sortColumn and sortOrder not validated against allowlist
String query = "SELECT * FROM products ORDER BY " + sortColumn + " " + sortOrder;
```

**Safe alternative:**

```java
PreparedStatement ps = connection.prepareStatement(
    "SELECT * FROM products WHERE name LIKE ?");
ps.setString(1, "%" + keyword + "%");
ResultSet rs = ps.executeQuery();
```

### 5.2 Command Injection (CWE-78)

**Pattern: `Runtime.exec()` with string concatenation**

```java
// Vulnerable — user input passed directly to shell command
String cmd = "ping -c 3 " + host;
Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
```

**Pattern: `ProcessBuilder` with shell invocation**

```java
// Vulnerable — domain from user input injected into shell command
String cmd = "nslookup " + domain;
ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
Process proc = pb.start();
```

**Safe alternative:**

```java
// Use argument array without shell interpretation
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "3", host);
Process proc = pb.start();
```

### 5.3 Cross-Site Scripting — XSS (CWE-79)

**Pattern: Stored XSS via string concatenation in HTML**

```java
// Vulnerable — post content rendered without escaping
String html = "<h2>" + post.getTitle() + "</h2>";
html += "<div>" + post.getContent() + "</div>";
```

**Pattern: Reflected XSS in search results**

```java
// Vulnerable — query parameter reflected back into page
String html = "<p>Results for: <em>" + query + "</em></p>";
```

**Pattern: XSS via `href` attribute (javascript: protocol)**

```java
String html = "<a href=\"" + userWebsite + "\">" + userWebsite + "</a>";
```

**Safe alternative:**

```java
import org.apache.commons.text.StringEscapeUtils;
String safeTitle = StringEscapeUtils.escapeHtml4(post.getTitle());
String html = "<h2>" + safeTitle + "</h2>";
```

### 5.4 Broken Access Control (CWE-200, CWE-284, CWE-639)

**Pattern: No authentication on sensitive endpoint**

```java
@GetMapping("/api/users/{userId}")
public ResponseEntity<?> getUserProfile(@PathVariable int userId) {
    Map<String, Object> user = users.get(userId);
    return ResponseEntity.ok(user); // Returns SSN, salary — no auth check
}
```

**Pattern: Client-controlled authorization header**

```java
String role = request.getHeader("X-User-Role");
if (role == null) role = "employee";
if (!"admin".equals(role)) {
    return ResponseEntity.status(403).body("Admin access required");
}
```

**Pattern: Missing object-level authorization**

```java
// Any authenticated user can access any document — no ownership check
Map<String, Object> doc = documents.get(docId);
return ResponseEntity.ok(doc);
```

### 5.5 Cryptographic Failures (CWE-327, CWE-328, CWE-330)

**Pattern: MD5 for password hashing**

```java
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest("admin123".getBytes());
String hexHash = DatatypeConverter.printHexBinary(hash).toLowerCase();
```

**Pattern: DES in ECB mode with hardcoded key**

```java
private static final String MASTER_KEY = "s3cr3t!!";
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
SecretKeySpec keySpec = new SecretKeySpec(MASTER_KEY.getBytes(), "DES");
cipher.init(Cipher.ENCRYPT_MODE, keySpec);
```

**Pattern: Predictable PRNG for session tokens**

```java
Random rng = new Random(System.currentTimeMillis());
StringBuilder token = new StringBuilder();
for (int i = 0; i < 32; i++) {
    token.append(CHARS.charAt(rng.nextInt(CHARS.length())));
}
```

**Safe alternative:**

```java
// Use BCrypt for password hashing
import org.mindrot.jbcrypt.BCrypt;
String hashed = BCrypt.hashpw(password, BCrypt.gensalt());

// Use SecureRandom for tokens
SecureRandom sr = new SecureRandom();
byte[] tokenBytes = new byte[32];
sr.nextBytes(tokenBytes);
```

### 5.6 Insecure Design (CWE-209, CWE-522)

**Pattern: Plaintext password storage**

```java
Map<String, Object> admin = new HashMap<>();
admin.put("username", "admin");
admin.put("password", "Adm1n_Pr0d!");
```

**Pattern: Verbose error responses**

```java
Map<String, Object> error = new HashMap<>();
error.put("error", "Report generation failed");
error.put("details", e.getMessage());
error.put("trace", Arrays.toString(e.getStackTrace()));
error.put("database", DATABASE_PATH);
return ResponseEntity.status(500).body(error);
```

**Pattern: User enumeration via distinct error messages**

```java
// Different messages for "user not found" vs. "wrong password"
return ResponseEntity.status(404).body("No account found for username '" + username + "'");
// vs.
return ResponseEntity.status(401).body("Incorrect password. Attempts: " + failedAttempts);
```

### 5.7 Security Misconfiguration (CWE-16, CWE-611)

**Pattern: XXE via `DocumentBuilderFactory` without secure configuration**

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Missing: dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
// Missing: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(rawXml)));
```

**Pattern: XXE via `SAXParserFactory`**

```java
SAXParserFactory spf = SAXParserFactory.newInstance();
// No secure processing features set
SAXParser parser = spf.newSAXParser();
parser.parse(inputSource, handler);
```

**Pattern: Overly permissive CORS**

```java
String origin = request.getHeader("Origin");
response.setHeader("Access-Control-Allow-Origin", origin != null ? origin : "*");
response.setHeader("Access-Control-Allow-Credentials", "true");
```

**Pattern: Verbose error handler exposing internals**

```java
@ExceptionHandler(Exception.class)
public ResponseEntity<?> handleException(Exception e) {
    Map<String, Object> body = new HashMap<>();
    body.put("trace", Arrays.toString(e.getStackTrace()));
    body.put("message", e.getMessage());
    return ResponseEntity.status(500).body(body);
}
```

### 5.8 Vulnerable and Outdated Components (CWE-1104)

**Pattern: Unsafe YAML loading with SnakeYAML**

```java
Yaml yaml = new Yaml(); // Default constructor allows arbitrary object instantiation
Object data = yaml.load(untrustedInput);
```

**Pattern: Outdated dependencies in `pom.xml`**

```xml
<!-- Vulnerable Spring Boot version -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.5.0</version> <!-- Known CVEs -->
</parent>
```

### 5.9 Integrity Failures — Deserialization (CWE-502, CWE-829)

**Pattern: Java native deserialization of untrusted data**

```java
byte[] rawBytes = Base64.getDecoder().decode(payload);
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(rawBytes));
Object obj = ois.readObject(); // Arbitrary code execution via gadget chains
```

**Pattern: Unsafe YAML deserialization**

```java
Yaml yaml = new Yaml();
Object data = yaml.load(untrustedYamlString); // Arbitrary object instantiation
```

**Pattern: `XMLDecoder` on untrusted input**

```java
XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlBytes));
Object obj = decoder.readObject(); // Remote code execution
```

**Safe alternative:**

```java
// Use JSON (Jackson) instead of Java serialization
ObjectMapper mapper = new ObjectMapper();
MyData data = mapper.readValue(jsonString, MyData.class);

// Use SafeConstructor for YAML
Yaml yaml = new Yaml(new SafeConstructor());
```

### 5.10 Logging and Monitoring Failures (CWE-778)

**Pattern: Credentials in API responses**

```java
Map<String, Object> response = new HashMap<>();
response.put("token", token);
response.put("password", user.get("password"));
response.put("apiKey", user.get("apiKey"));
return ResponseEntity.ok(response);
```

**Pattern: No audit logging for privilege changes**

```java
targetUser.put("role", newRole); // Role changed with no log entry
```

### 5.11 SSRF (CWE-918)

**Pattern: Unrestricted URL fetch**

```java
URL url = new URL(userProvidedUrl);
InputStream is = url.openStream(); // No validation of target host
```

**Pattern: Incomplete blocklist**

```java
List<String> blocked = Arrays.asList("localhost", "127.0.0.1");
// Missing: 0.0.0.0, [::1], 169.254.x.x, decimal IP representations
```

**Pattern: Open proxy via user-supplied base URL**

```java
String baseUrl = request.getParameter("base_url");
String fullUrl = baseUrl + path;
HttpURLConnection conn = (HttpURLConnection) new URL(fullUrl).openConnection();
```

### 5.12 Race Conditions (CWE-362)

**Pattern: Check-then-act without synchronization**

```java
public boolean withdraw(double amount) {
    if (this.balance >= amount) {
        Thread.sleep(1); // Simulates processing delay
        this.balance -= amount; // Another thread may have changed balance
        return true;
    }
    return false;
}
```

**Pattern: Read-modify-write on shared `HashMap`**

```java
int count = counters.getOrDefault(key, 0);
count++;
counters.put(key, count); // Lost update if concurrent
```

**Safe alternative:**

```java
public synchronized boolean withdraw(double amount) {
    if (this.balance >= amount) {
        this.balance -= amount;
        return true;
    }
    return false;
}

// Or use ConcurrentHashMap with atomic operations
counters.merge(key, 1, Integer::sum);
```

### 5.13 NULL Pointer Dereference (CWE-476)

**Pattern: Unchecked return value from `Map.get()`**

```java
Map<String, Object> user = users.get(userId);
String name = (String) user.get("name"); // NPE if userId not found
```

**Pattern: Missing null check after external lookup**

```java
Connection conn = dataSource.getConnection();
ResultSet rs = stmt.executeQuery(query);
rs.next();
String value = rs.getString("column"); // NPE if no rows returned
```

**Safe alternative:**

```java
Map<String, Object> user = users.get(userId);
if (user == null) {
    throw new NotFoundException("User not found: " + userId);
}
```

### 5.14 Integer Overflow (CWE-190)

**Pattern: Unchecked arithmetic on `int` or `long`**

```java
int total = quantity * priceInCents; // Overflow if both are large
```

**Pattern: Casting `long` to `int` without range check**

```java
long bigValue = computeLargeValue();
int result = (int) bigValue; // Silent truncation
```

**Safe alternative:**

```java
int total = Math.multiplyExact(quantity, priceInCents); // Throws ArithmeticException on overflow

// Or use Math.toIntExact for safe narrowing
int result = Math.toIntExact(bigValue);
```

---

## 6. Cross-References to Examples

The table below maps each vulnerability class to the Java source file and companion documentation in this project. All paths are relative to the `docs/` directory.

| Vulnerability Class | Source File | Companion Doc |
|---|---|---|
| SQL Injection (CWE-89) | [`../injection/sql-injection/java/App.java`](../injection/sql-injection/java/App.java) | [`../injection/sql-injection/java/App_SECURITY.md`](../injection/sql-injection/java/App_SECURITY.md) |
| Command Injection (CWE-78) | [`../injection/command-injection/java/App.java`](../injection/command-injection/java/App.java) | [`../injection/command-injection/java/App_SECURITY.md`](../injection/command-injection/java/App_SECURITY.md) |
| Cross-Site Scripting (CWE-79) | [`../injection/xss/java/App.java`](../injection/xss/java/App.java) | [`../injection/xss/java/App_SECURITY.md`](../injection/xss/java/App_SECURITY.md) |
| Broken Access Control (CWE-200, CWE-284, CWE-639) | [`../broken-access-control/java/App.java`](../broken-access-control/java/App.java) | [`../broken-access-control/java/App_SECURITY.md`](../broken-access-control/java/App_SECURITY.md) |
| Cryptographic Failures (CWE-327, CWE-328, CWE-330) | [`../cryptographic-failures/java/App.java`](../cryptographic-failures/java/App.java) | [`../cryptographic-failures/java/App_SECURITY.md`](../cryptographic-failures/java/App_SECURITY.md) |
| Insecure Design (CWE-209, CWE-522) | [`../insecure-design/java/App.java`](../insecure-design/java/App.java) | [`../insecure-design/java/App_SECURITY.md`](../insecure-design/java/App_SECURITY.md) |
| Security Misconfiguration (CWE-16, CWE-611) | [`../security-misconfiguration/java/App.java`](../security-misconfiguration/java/App.java) | [`../security-misconfiguration/java/App_SECURITY.md`](../security-misconfiguration/java/App_SECURITY.md) |
| Vulnerable Components (CWE-1104) | [`../vulnerable-components/java/App.java`](../vulnerable-components/java/App.java) | [`../vulnerable-components/java/App_SECURITY.md`](../vulnerable-components/java/App_SECURITY.md) |
| Auth Failures (CWE-287, CWE-307, CWE-798) | [`../auth-failures/java/App.java`](../auth-failures/java/App.java) | [`../auth-failures/java/App_SECURITY.md`](../auth-failures/java/App_SECURITY.md) |
| Integrity Failures (CWE-502, CWE-829) | [`../integrity-failures/java/App.java`](../integrity-failures/java/App.java) | [`../integrity-failures/java/App_SECURITY.md`](../integrity-failures/java/App_SECURITY.md) |
| Logging/Monitoring Failures (CWE-778) | [`../logging-monitoring-failures/java/App.java`](../logging-monitoring-failures/java/App.java) | [`../logging-monitoring-failures/java/App_SECURITY.md`](../logging-monitoring-failures/java/App_SECURITY.md) |
| SSRF (CWE-918) | [`../ssrf/java/App.java`](../ssrf/java/App.java) | [`../ssrf/java/App_SECURITY.md`](../ssrf/java/App_SECURITY.md) |
| NULL Pointer Dereference (CWE-476) | [`../memory-safety/null-pointer-deref/java/App.java`](../memory-safety/null-pointer-deref/java/App.java) | [`../memory-safety/null-pointer-deref/java/App_SECURITY.md`](../memory-safety/null-pointer-deref/java/App_SECURITY.md) |
| Integer Overflow (CWE-190) | [`../integer-overflow/java/App.java`](../integer-overflow/java/App.java) | [`../integer-overflow/java/App_SECURITY.md`](../integer-overflow/java/App_SECURITY.md) |
| Race Condition (CWE-362) | [`../race-condition/java/App.java`](../race-condition/java/App.java) | [`../race-condition/java/App_SECURITY.md`](../race-condition/java/App_SECURITY.md) |

---

## 7. Quick-Reference Checklist

Use this checklist during Java code reviews. Each item maps to a vulnerability class covered in this guide.

- [ ] **Input validation** — All user inputs (`@RequestParam`, `@PathVariable`, `@RequestBody`, headers, cookies) are validated and sanitized before use in SQL, shell commands, HTML, or URLs
- [ ] **Parameterized queries** — All SQL queries use `PreparedStatement` with `?` placeholders, never `Statement` with string concatenation
- [ ] **No shell invocation with user input** — `Runtime.exec()` and `ProcessBuilder` do not pass user input through `sh -c`; arguments are passed as separate array elements
- [ ] **Output encoding** — All user-controlled data rendered in HTML is escaped (via `StringEscapeUtils.escapeHtml4()`, Thymeleaf autoescaping, or equivalent)
- [ ] **Authentication on every endpoint** — All sensitive endpoints verify the session/token before processing (Spring Security, `@PreAuthorize`, or manual checks)
- [ ] **Server-side authorization** — Role and permission checks use server-side session data, not client-supplied headers
- [ ] **Object-level access control** — Resource access verifies the requesting user owns or is authorized for the specific resource
- [ ] **Strong password hashing** — Passwords are hashed with BCrypt, SCrypt, or Argon2 — never MD5 or SHA-1
- [ ] **Modern encryption** — AES-GCM or AES-CBC with HMAC is used; no DES, no ECB mode
- [ ] **Cryptographic randomness** — Tokens and secrets use `SecureRandom`, not `java.util.Random`
- [ ] **No hardcoded secrets** — API keys, passwords, and encryption keys are loaded from environment variables, a secrets manager, or externalized configuration
- [ ] **Safe deserialization** — `ObjectInputStream.readObject()` is never called on untrusted data; JSON (Jackson/Gson) is preferred over Java native serialization
- [ ] **Safe YAML parsing** — `SnakeYAML` uses `SafeConstructor`; default `Yaml()` constructor is not used with untrusted input
- [ ] **XXE prevention** — `DocumentBuilderFactory` and `SAXParserFactory` disable external entities (`FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`)
- [ ] **SSRF protection** — Outbound HTTP requests validate URLs against an allowlist; internal/metadata IPs are blocked
- [ ] **Minimal error responses** — Error responses do not include stack traces, database paths, or internal configuration; `server.error.include-stacktrace` is set to `never`
- [ ] **Secure CORS** — `Access-Control-Allow-Origin` is set to specific trusted origins, not `*` or reflected from the request
- [ ] **Audit logging** — Authentication events, privilege changes, and sensitive operations are logged
- [ ] **No credentials in responses** — API responses do not include passwords, API keys, or other secrets
- [ ] **Thread safety** — Shared mutable state accessed by multiple threads uses `synchronized`, `ReentrantLock`, or concurrent collections (`ConcurrentHashMap`, `AtomicInteger`)
- [ ] **Null safety** — Return values from `Map.get()`, database queries, and external calls are checked for `null` before use
- [ ] **Integer overflow protection** — Arithmetic on `int`/`long` uses `Math.addExact()`, `Math.multiplyExact()`, or `Math.toIntExact()` where overflow is possible
- [ ] **Dependency hygiene** — `pom.xml` pins dependency versions; dependencies are checked for known CVEs with `mvn dependency-check:check` (OWASP Dependency-Check) or `mvn versions:display-dependency-updates`
