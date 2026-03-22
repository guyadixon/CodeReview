# Security Companion Document: main.cpp

## Vulnerability: Overly Permissive CORS with Wildcard Origin and Credentials

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L62-L68  

### Description
The `add_cors_headers` function sets `Access-Control-Allow-Origin` to `*` (from the `allowed_origins` global), `Access-Control-Allow-Credentials` to `true`, and `Access-Control-Allow-Headers` to `*` on every response. The `Server` and `X-Powered-By` headers also reveal the exact library version.

### Exploitation Scenario
A developer changes the CORS logic to reflect the request origin (a common "fix" for the `*` with credentials browser restriction). Once reflected, any website can make authenticated cross-origin requests. The unrestricted methods and headers allow cross-origin preflight requests for any operation.

### Remediation Guidance
Set specific allowed origins:
```cpp
static void add_cors_headers(httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", "https://app.acmecorp.io");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
}
```

### Complexity Rationale
This is rated Moderate because the CORS headers are set in a centralized helper function that appears well-structured. A reviewer must understand the interaction between wildcard origins, credentials, and browser CORS enforcement.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize the combination of `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` and understand the CORS specification implications.

---

## Vulnerability: Server Version and Technology Disclosure via Headers

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L66-L67  

### Description
Every response includes `Server: cpp-httplib/0.14.3 (Linux)` and `X-Powered-By: cpp-httplib` headers, revealing the exact HTTP library version and operating system. This information helps attackers identify known vulnerabilities in the specific library version.

### Exploitation Scenario
An attacker inspects response headers to learn the server uses `cpp-httplib/0.14.3` on Linux. The attacker searches CVE databases for known vulnerabilities in this version and crafts targeted exploits.

### Remediation Guidance
Remove version-revealing headers:
```cpp
/* Do not set Server or X-Powered-By headers */
```

### Complexity Rationale
This is rated Obvious because the version strings are plaintext constants used directly in header values, immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match `Server` and `X-Powered-By` header patterns with version strings through simple string matching.

---

## Vulnerability: XML External Entity (XXE) Processing in Product Import

**CWE:** CWE-611  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L133-L135  

### Description
The product import endpoint calls `xmlReadMemory()` with flags `XML_PARSE_DTDLOAD | XML_PARSE_NOENT`, which enables DTD loading and entity substitution. This allows the libxml2 parser to resolve external entity declarations in user-supplied XML, enabling file reading and SSRF attacks.

### Exploitation Scenario
An attacker sends a POST to `/api/products/import` with:
```xml
<?xml version="1.0"?>
<!DOCTYPE products [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<products><product><name>&xxe;</name><sku>X</sku><price>0</price><stock>0</stock></product></products>
```
The server resolves the entity and returns the contents of `/etc/passwd` in the product name field.

### Remediation Guidance
Disable DTD loading and entity substitution:
```cpp
xmlDocPtr doc = xmlReadMemory(req.body.c_str(), req.body.size(),
                               "noname.xml", nullptr,
                               XML_PARSE_NOERROR | XML_PARSE_NONET);
```

### Complexity Rationale
This is rated Moderate because the `XML_PARSE_DTDLOAD | XML_PARSE_NOENT` flags are explicit but require knowledge of libxml2's parsing options and their security implications.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools have well-known rules for detecting `XML_PARSE_NOENT` and `XML_PARSE_DTDLOAD` flags in libxml2 calls.

---

## Vulnerability: Debug Mode and Insecure Default Configuration

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L31-L34  

### Description
The application has `debug_mode` set to `true`, `tls_verify` set to `false`, and `log_level` set to `"DEBUG"` as global defaults. Debug mode enables verbose output, TLS verification is disabled (allowing man-in-the-middle attacks), and DEBUG logging may expose sensitive request data.

### Exploitation Scenario
An attacker on the network performs a man-in-the-middle attack on outbound TLS connections because certificate verification is disabled. Debug logging writes sensitive request data to log files that may be accessible through other vulnerabilities.

### Remediation Guidance
Set secure defaults:
```cpp
static bool debug_mode = false;
static bool tls_verify = true;
static std::string log_level = "WARNING";
```

### Complexity Rationale
This is rated Obvious because the insecure defaults are plaintext global variable assignments at the top of the file, immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match patterns like `tls_verify = false` and `debug_mode = true` through simple value analysis.

---

## Vulnerability: Diagnostics Endpoint Exposes Database Credentials and Build Information

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L178-L189  

### Description
The `/api/admin/diagnostics` endpoint returns the database host, username, and password, the server banner, product count, and compile date/time in a structured JSON response. While protected by a static admin token, the token is hardcoded in the source code. The compile information reveals when the binary was built.

### Exploitation Scenario
An attacker who discovers the hardcoded token `super-admin-token-2024` sends `GET /api/admin/diagnostics` and receives the database password `Pg_Pr0d#2024`, the database host, and build timestamps. The attacker uses the database credentials for direct access to the production database.

### Remediation Guidance
Remove sensitive data from diagnostic responses:
```cpp
json resp = {
    {"product_count", products.size()},
    {"server_banner", "config-api"}
};
```

### Complexity Rationale
This is rated Nuanced because the endpoint is admin-protected and returns data in a structured JSON format that appears intentional for operational monitoring. A reviewer must recognize that even admin-only endpoints should not expose raw database credentials, and that the hardcoded admin token provides weak protection.

### Detection Difficulty Rationale
This is rated Likely_Missed because the credentials flow through nlohmann::json serialization, which SAST tools may not trace effectively. The admin token check further reduces the likelihood of flagging.
