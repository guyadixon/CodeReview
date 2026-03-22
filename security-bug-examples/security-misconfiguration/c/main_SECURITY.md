# Security Companion Document: main.c

## Vulnerability: Overly Permissive CORS with Wildcard Origin and Credentials

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L84-L90  

### Description
The `send_json` helper function sets `Access-Control-Allow-Origin` to `*` (from the `allowed_origins` global), `Access-Control-Allow-Credentials` to `true`, and `Access-Control-Allow-Headers` to `*` on every response. While browsers block `Access-Control-Allow-Origin: *` with credentials, the combination of wildcard headers and methods with the intent to allow credentials indicates a misconfigured CORS policy that would be exploitable if the origin were reflected instead of wildcarded.

### Exploitation Scenario
A developer changes the CORS logic to reflect the request origin (a common "fix" for the `*` with credentials browser restriction). Once reflected, any website can make authenticated cross-origin requests. Even with the current `*` configuration, the `Access-Control-Allow-Methods` includes DELETE and the headers are unrestricted, allowing cross-origin preflight requests for any method.

### Remediation Guidance
Set specific allowed origins and remove credentials support unless needed:
```c
MHD_add_response_header(resp, "Access-Control-Allow-Origin", "https://app.acmecorp.io");
MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET, POST, PUT");
MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
```

### Complexity Rationale
This is rated Moderate because the CORS headers are set in a centralized helper function. A reviewer must understand the interaction between wildcard origins, credentials, and the browser's CORS enforcement rules.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize the combination of `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` and understand the CORS specification implications.

---

## Vulnerability: Server Version and Technology Disclosure via Headers

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L85-L86  

### Description
Every response includes `Server: libmicrohttpd/0.9.77 (Linux)` and `X-Powered-By: libmicrohttpd` headers, revealing the exact HTTP library version and operating system. This information helps attackers identify known vulnerabilities in the specific library version.

### Exploitation Scenario
An attacker sends any request and inspects response headers to learn the server uses `libmicrohttpd/0.9.77` on Linux. The attacker searches CVE databases for known vulnerabilities in this version and crafts targeted exploits.

### Remediation Guidance
Remove or suppress version-revealing headers:
```c
/* Do not add Server or X-Powered-By headers */
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
**Affected Lines:** L131-L132  

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
```c
xmlDocPtr doc = xmlReadMemory(body, strlen(body), "noname.xml", NULL,
                               XML_PARSE_NOERROR | XML_PARSE_NONET);
```
Or use `xmlCtxtReadMemory` with a parser context that has entity loading disabled.

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
**Affected Lines:** L33-L36  

### Description
The application has `debug_mode` set to `1`, `tls_verify` set to `0`, and `log_level` set to `"DEBUG"` as compile-time defaults. Debug mode enables verbose output, TLS verification is disabled (allowing man-in-the-middle attacks on outbound connections), and DEBUG logging may expose sensitive request data in log files.

### Exploitation Scenario
An attacker on the network performs a man-in-the-middle attack on any outbound TLS connections made by the application (e.g., to the database or external services) because TLS certificate verification is disabled. The debug logging writes sensitive request data to log files that may be accessible through other vulnerabilities.

### Remediation Guidance
Set secure defaults:
```c
static int debug_mode = 0;
static int tls_verify = 1;
static const char *log_level = "WARNING";
```

### Complexity Rationale
This is rated Obvious because the insecure defaults are plaintext global variable assignments at the top of the file, immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match patterns like `tls_verify = 0` and `debug_mode = 1` through simple value analysis.

---

## Vulnerability: Diagnostics Endpoint Exposes Database Credentials and Build Information

**CWE:** CWE-16  
**OWASP:** A05  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L192-L203  

### Description
The `/api/admin/diagnostics` endpoint returns the database host, username, and password, the server banner, product count, and compile date/time. While protected by a static admin token, the token is hardcoded in the source code. The compile information reveals when the binary was built, aiding version fingerprinting.

### Exploitation Scenario
An attacker who discovers the hardcoded token `super-admin-token-2024` sends `GET /api/admin/diagnostics` and receives the database password `Pg_Pr0d#2024`, the database host, and build timestamps. The attacker uses the database credentials for direct access.

### Remediation Guidance
Remove sensitive data from diagnostic responses:
```c
snprintf(resp, sizeof(resp),
    "{\"product_count\":%d,\"server_banner\":\"%s\"}",
    product_count, "config-api");
```

### Complexity Rationale
This is rated Moderate because the endpoint is admin-protected, which may seem sufficient. A reviewer must recognize that exposing raw database credentials through any endpoint is excessive information disclosure.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect hardcoded credential constants being formatted into response strings, but the admin token check may cause tools to deprioritize the finding.
