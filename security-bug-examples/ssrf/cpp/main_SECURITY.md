# Security Companion Document: main.cpp

## Vulnerability: Direct URL Fetch from User Input

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L174-L203  

### Description
The `/api/fetch-url` handler accepts a URL from the JSON request body and passes it directly to `do_http_get` without any validation. The `do_http_get` function uses cpp-httplib to make an HTTP request to the user-supplied URL. An attacker can supply internal network addresses, cloud metadata endpoints, or localhost services.

### Exploitation Scenario
An attacker sends `POST /api/fetch-url` with `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` to retrieve AWS IAM credentials. The server's HTTP client fetches the metadata service and returns the response body.

### Remediation Guidance
Validate URLs before fetching by resolving the hostname and checking against private/reserved IP ranges:
```cpp
#include <netdb.h>
#include <arpa/inet.h>
struct addrinfo *result;
if (getaddrinfo(parts.host.c_str(), nullptr, nullptr, &result) == 0) {
    auto *addr = (struct sockaddr_in *)result->ai_addr;
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    if ((ip >> 24) == 127 || (ip >> 24) == 10) {
        freeaddrinfo(result);
        // block request
    }
    freeaddrinfo(result);
}
```

### Complexity Rationale
This is rated Obvious because user input flows directly from JSON parsing into `do_http_get(url)` with zero intermediate validation. The taint path is a single step.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the direct data flow from user input to the HTTP client call. This is a textbook SSRF pattern.

---

## Vulnerability: Incomplete Blocklist Bypass in URL Preview

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L205-L238  

### Description
The `/api/preview` handler parses the target URL and checks if the host is `localhost` or `127.0.0.1`. This blocklist is trivially incomplete. It does not block other loopback addresses (`127.0.0.2`), private network ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`), IPv6 loopback (`[::1]`), or cloud metadata IPs (`169.254.169.254`).

### Exploitation Scenario
An attacker sends `GET /api/preview?target=http://169.254.169.254/latest/meta-data/` to access cloud metadata. The hostname `169.254.169.254` does not match `localhost` or `127.0.0.1`, so the request proceeds.

### Remediation Guidance
Resolve the hostname and validate the resolved IP address before making the request.

### Complexity Rationale
This is rated Moderate because a blocklist is present, which may satisfy a cursory review. The reviewer must recognize the many alternative representations of internal addresses.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect the URL fetch but evaluating blocklist completeness requires understanding IP address representations.

---

## Vulnerability: Webhook Callback Without Re-validation

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L275-L306  

### Description
The `/api/webhooks/:id/test` handler retrieves a stored webhook callback URL from the registry and passes it to `do_http_post` without re-validating the destination. The registration handler only checks the URL scheme prefix. At test time, the stored URL is used directly, creating a two-step SSRF.

### Exploitation Scenario
An attacker registers a webhook with `callback_url` set to `http://169.254.169.254/latest/meta-data/`. The registration succeeds because only the scheme prefix is validated. The attacker then triggers the test endpoint, causing the server to POST to the metadata endpoint.

### Remediation Guidance
Re-validate the callback URL at delivery time by resolving the hostname and checking the IP before making the request.

### Complexity Rationale
This is rated Moderate because the vulnerability spans two handler lambdas (registration and test). The scheme check during registration may give a false sense of security.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must track data flow from the webhook registry (storage) to the HTTP request, requiring interprocedural analysis across two handler lambdas.

---

## Vulnerability: Metadata Endpoint Check Bypassable via DNS Rebinding

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L308-L353  

### Description
The `/api/integrations/import` handler parses the config URL and checks if the host starts with `169.254` using `parts.host.find("169.254") == 0`. This check is performed on the hostname string before DNS resolution. An attacker can use DNS rebinding where a custom domain initially resolves to a safe IP but later resolves to `169.254.169.254`.

### Exploitation Scenario
An attacker controls DNS for `evil.example.com` with a short TTL. The hostname `evil.example.com` does not start with `169.254`, so the check passes. When cpp-httplib resolves the domain, the DNS record has changed to `169.254.169.254`. The server fetches the metadata and returns it.

### Remediation Guidance
Resolve the hostname before making the request and validate the resolved IP address.

### Complexity Rationale
This is rated Nuanced because a metadata protection check is present and appears functional. Understanding the bypass requires knowledge of DNS rebinding and the TOCTOU gap.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools generally cannot detect DNS rebinding vulnerabilities. The tool sees a hostname check that appears to be a valid mitigation.

---

## Vulnerability: Service Proxy with Arbitrary base_url Fallback

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L355-L397  

### Description
The `/api/proxy` handler maps known service names to internal URLs but falls back to a user-supplied `base_url` query parameter when the service is not found in the map. The `base_url` is concatenated with `path` and fetched without validation, turning the proxy into an open relay.

### Exploitation Scenario
An attacker sends `GET /api/proxy?service=unknown&base_url=http://169.254.169.254&path=/latest/meta-data/` to access cloud metadata. Since `unknown` is not in the service map, the server uses the attacker-controlled `base_url`.

### Remediation Guidance
Remove the `base_url` fallback:
```cpp
auto it = service_map.find(service);
if (it == service_map.end()) {
    res.set_content(R"({"error":"Unknown service"})", "application/json");
    res.status = 400;
    return;
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability is hidden within a legitimate service proxy pattern. The fallback to user input only occurs when the service lookup fails.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must understand the conditional logic where user-supplied `base_url` is only used as a fallback. The primary path uses a hardcoded service map.
