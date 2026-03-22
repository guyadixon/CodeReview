# Security Companion Document: App.java

## Vulnerability: Direct URL Fetch from User Input

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L103-L120  

### Description
The `/api/fetch-url` endpoint accepts a URL from the request body and passes it directly to `fetchRemoteContent`, which opens an `HttpURLConnection` to the user-supplied URL without any validation. An attacker can supply internal network addresses, cloud metadata endpoints, or localhost services.

### Exploitation Scenario
An attacker sends `POST /api/fetch-url` with `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` to retrieve AWS IAM credentials. The server opens a connection to the metadata service and returns the response body containing temporary access keys.

### Remediation Guidance
Validate URLs before fetching by resolving the hostname and checking against private/reserved IP ranges:
```java
InetAddress addr = InetAddress.getByName(new URI(url).getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
    return Map.of("error", "Blocked destination");
}
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `body.getOrDefault("url", "")` into `fetchRemoteContent(url)` with zero intermediate validation. The taint path is a single step.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the direct data flow from `@RequestBody` to `HttpURLConnection.openConnection()`. This is a textbook SSRF pattern.

---

## Vulnerability: Incomplete Blocklist Bypass in URL Preview

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L122-L146  

### Description
The `/api/preview` endpoint blocks requests to `localhost` and `127.0.0.1` but the blocklist is trivially incomplete. It does not block other loopback addresses (`127.0.0.2`, `0:0:0:0:0:0:0:1`), private network ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`), or cloud metadata IPs (`169.254.169.254`). Java's `URI.getHost()` returns the raw hostname string, so hex or octal IP representations also bypass the check.

### Exploitation Scenario
An attacker sends `GET /api/preview?target=http://[::1]:8080/admin` to access an internal service via the IPv6 loopback address. The string `[::1]` does not match `localhost` or `127.0.0.1` in the blocklist, so the request proceeds.

### Remediation Guidance
Resolve the hostname and validate the resolved IP address:
```java
InetAddress addr = InetAddress.getByName(uri.getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
    return Map.of("error", "Blocked host");
}
```

### Complexity Rationale
This is rated Moderate because a blocklist is present, which may satisfy a cursory review. The reviewer must recognize the many alternative representations of internal addresses that bypass string comparison.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect the URL fetch but evaluating blocklist completeness requires understanding IP address representations, which depends on rule sophistication.

---

## Vulnerability: Webhook Callback Without Re-validation

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L175-L203  

### Description
The `/api/webhooks/{webhookId}/test` endpoint retrieves a stored webhook callback URL and makes an HTTP POST to it without re-validating the destination. The registration endpoint only checks the URL scheme, not the host. At test time, the stored URL is used directly with `HttpURLConnection`, creating a two-step SSRF.

### Exploitation Scenario
An attacker registers a webhook with `callbackUrl` set to `http://169.254.169.254/latest/meta-data/`. The registration succeeds because only the scheme is validated. The attacker then triggers `POST /api/webhooks/<id>/test`, causing the server to POST to the metadata endpoint.

### Remediation Guidance
Re-validate the callback URL at delivery time:
```java
InetAddress addr = InetAddress.getByName(new URI(callbackUrl).getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
    return Map.of("error", "Blocked callback destination");
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans two endpoints (registration and test). The scheme check during registration may give a false sense of security.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must track data flow from the webhook registry (storage) to the HTTP request, requiring interprocedural analysis across two request handlers.

---

## Vulnerability: Metadata Endpoint Check Bypassable via DNS Rebinding

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L205-L232  

### Description
The `/api/integrations/import` endpoint checks whether the hostname starts with `169.254` to block cloud metadata access. This check is performed on the hostname string before DNS resolution. An attacker can use DNS rebinding where a custom domain initially resolves to a safe IP but later resolves to `169.254.169.254`. The check also fails for hostnames like `metadata.internal` that resolve to the metadata IP.

### Exploitation Scenario
An attacker controls DNS for `evil.example.com` with a short TTL. The first lookup returns `1.2.3.4` (passing the hostname check), but when `HttpURLConnection` resolves the domain, the DNS record has changed to `169.254.169.254`. The server fetches the metadata and returns it.

### Remediation Guidance
Resolve the hostname before making the request and validate the resolved IP:
```java
InetAddress addr = InetAddress.getByName(uri.getHost());
if (addr.isLinkLocalAddress()) {
    return Map.of("error", "Blocked destination");
}
```

### Complexity Rationale
This is rated Nuanced because a metadata protection check is present and appears functional. Understanding the bypass requires knowledge of DNS rebinding and the TOCTOU gap between hostname validation and DNS resolution during the HTTP request.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools generally cannot detect DNS rebinding vulnerabilities. The tool sees a hostname check that appears to be a valid mitigation.

---

## Vulnerability: Service Proxy with Arbitrary base_url Fallback

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L234-L260  

### Description
The `/api/proxy` endpoint maps known service names to internal URLs but falls back to a user-supplied `baseUrl` parameter when the service is not recognized. The `baseUrl` is concatenated with `path` and fetched without validation, turning the proxy into an open relay.

### Exploitation Scenario
An attacker sends `GET /api/proxy?service=unknown&baseUrl=http://169.254.169.254&path=/latest/meta-data/` to access cloud metadata. Since `unknown` is not in the service map, the server uses the attacker-controlled `baseUrl`.

### Remediation Guidance
Remove the `baseUrl` fallback:
```java
String resolvedBase = serviceMap.getOrDefault(service, "");
if (resolvedBase.isEmpty()) return Map.of("error", "Unknown service");
```

### Complexity Rationale
This is rated Nuanced because the vulnerability is hidden within a legitimate service proxy pattern. The fallback to user input only occurs when the service lookup fails, a secondary code path easily overlooked.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must understand the conditional logic where user-supplied `baseUrl` is only used as a fallback. The primary path uses a hardcoded service map, which appears safe.
