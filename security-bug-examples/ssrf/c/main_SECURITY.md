# Security Companion Document: main.c

## Vulnerability: Direct URL Fetch from User Input

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L183-L202  

### Description
The `handle_fetch_url` function extracts a URL from the JSON request body and passes it directly to `fetch_remote` (which uses libcurl) without any validation. An attacker can supply internal network addresses, cloud metadata endpoints, or localhost services, causing the server to make requests on their behalf.

### Exploitation Scenario
An attacker sends `POST /api/fetch-url` with `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` to retrieve AWS IAM credentials. The server's libcurl client fetches the metadata service and returns the response body.

### Remediation Guidance
Validate URLs before fetching by resolving the hostname and checking against private/reserved IP ranges:
```c
struct addrinfo *res;
if (getaddrinfo(hostname, NULL, NULL, &res) == 0) {
    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    if ((ip >> 24) == 127 || (ip >> 24) == 10 || (ip & 0xFFFF0000) == 0xA9FE0000) {
        freeaddrinfo(res);
        return send_json(conn, 403, "{\"error\":\"Blocked destination\"}");
    }
    freeaddrinfo(res);
}
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `extract_json_string` into `fetch_remote(url, &result)` with zero intermediate validation. The taint path is a single step.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the direct data flow from user input to `curl_easy_setopt(curl, CURLOPT_URL, url)`. This is a textbook SSRF pattern.

---

## Vulnerability: Incomplete Blocklist Bypass in URL Preview

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L204-L229  

### Description
The `handle_preview` function uses `strstr` to check if the target URL contains `localhost` or `127.0.0.1`. This substring check is slightly broader than hostname-only checks but still incomplete. It does not block other loopback addresses (`127.0.0.2`), private network ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`), IPv6 loopback (`[::1]`), or cloud metadata IPs (`169.254.169.254`).

### Exploitation Scenario
An attacker sends `GET /api/preview?target=http://169.254.169.254/latest/meta-data/` to access cloud metadata. The string `169.254.169.254` does not match `localhost` or `127.0.0.1`, so the request proceeds and the server fetches the metadata endpoint.

### Remediation Guidance
Resolve the hostname to an IP address and check against all private/reserved ranges:
```c
struct addrinfo *res;
if (getaddrinfo(hostname, NULL, NULL, &res) == 0) {
    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    if ((ip >> 24) == 127 || (ip >> 24) == 10 || (ip & 0xFFFF0000) == 0xA9FE0000) {
        freeaddrinfo(res);
        return send_json(conn, 403, "{\"error\":\"Blocked host\"}");
    }
    freeaddrinfo(res);
}
```

### Complexity Rationale
This is rated Moderate because a blocklist check is present using `strstr`, which may satisfy a cursory review. The reviewer must recognize that the blocklist is incomplete and does not cover all internal address representations.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect the URL fetch but evaluating the completeness of a string-based blocklist requires understanding of IP address representations.

---

## Vulnerability: Webhook Callback Without Re-validation

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L257-L288  

### Description
The `handle_test_webhook` function retrieves a stored webhook callback URL and passes it directly to `curl_easy_setopt(curl, CURLOPT_URL, ...)` without re-validating the destination. The registration function only checks the URL scheme. At test time, the stored URL is used directly, creating a two-step SSRF.

### Exploitation Scenario
An attacker registers a webhook with `callback_url` set to `http://169.254.169.254/latest/meta-data/`. The registration succeeds because only the scheme prefix is validated. The attacker then triggers `POST /api/webhooks/<id>/test`, causing the server to POST to the metadata endpoint via libcurl.

### Remediation Guidance
Re-validate the callback URL at delivery time by resolving the hostname and checking the IP before making the request.

### Complexity Rationale
This is rated Moderate because the vulnerability spans two functions (registration and test). The scheme check during registration may give a false sense of security.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must track data flow from the webhook array (storage) to the libcurl request, requiring interprocedural analysis across two handler functions.

---

## Vulnerability: Metadata Endpoint Check Bypassable via DNS Rebinding

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L290-L318  

### Description
The `handle_import_config` function uses `strstr(config_url, "169.254")` to block cloud metadata access. This check is performed on the URL string before DNS resolution. An attacker can use DNS rebinding where a custom domain initially resolves to a safe IP but later resolves to `169.254.169.254`. The check also fails for hostnames like `metadata.internal` that resolve to the metadata IP.

### Exploitation Scenario
An attacker controls DNS for `evil.example.com` with a short TTL. The URL `http://evil.example.com/config` does not contain `169.254`, so the check passes. When libcurl resolves the domain, the DNS record has changed to `169.254.169.254`. The server fetches the metadata and returns it.

### Remediation Guidance
Use libcurl's `CURLOPT_RESOLVE` option to pin DNS resolution, or resolve the hostname manually and validate the IP before making the request.

### Complexity Rationale
This is rated Nuanced because a metadata protection check is present and appears functional. Understanding the bypass requires knowledge of DNS rebinding and the TOCTOU gap between string validation and DNS resolution during the libcurl request.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools generally cannot detect DNS rebinding vulnerabilities. The tool sees a string check for `169.254` that appears to be a valid mitigation.

---

## Vulnerability: Service Proxy with Arbitrary base_url Fallback

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L320-L355  

### Description
The `handle_proxy` function maps known service names to internal URLs but falls back to a user-supplied `base_url` query parameter when the service is not recognized. The `base_url` is concatenated with `path` and fetched via libcurl without any validation, turning the proxy into an open relay.

### Exploitation Scenario
An attacker sends `GET /api/proxy?service=unknown&base_url=http://169.254.169.254&path=/latest/meta-data/` to access cloud metadata. Since `unknown` is not in the service map, the server uses the attacker-controlled `base_url`.

### Remediation Guidance
Remove the `base_url` fallback entirely:
```c
if (!resolved_base) {
    return send_json(conn, 400, "{\"error\":\"Unknown service\"}");
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability is hidden within a legitimate service proxy pattern. The fallback to user input only occurs when the service name lookup fails.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must understand the conditional logic where user-supplied `base_url` is only used as a fallback. The primary path uses hardcoded service URLs.
