# Security Companion Document: main.go

## Vulnerability: Direct URL Fetch from User Input

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L136-L157  

### Description
The `handleFetchURL` handler accepts a URL from the JSON request body and passes it directly to `doHTTPGet`, which uses `http.Client.Get` to fetch the URL without any validation. An attacker can supply internal network addresses, cloud metadata endpoints, or localhost services.

### Exploitation Scenario
An attacker sends `POST /api/fetch-url` with `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` to retrieve AWS IAM credentials. The server's HTTP client fetches the metadata service and returns the response body.

### Remediation Guidance
Validate URLs before fetching by resolving the hostname and checking against private/reserved IP ranges:
```go
host := parsed.Hostname()
ips, err := net.LookupIP(host)
for _, ip := range ips {
    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
        c.JSON(403, gin.H{"error": "Blocked destination"})
        return
    }
}
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `req.URL` into `doHTTPGet(req.URL)` with zero intermediate validation. The taint path is a single step.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the direct data flow from JSON binding to `http.Client.Get`. This is a textbook SSRF pattern.

---

## Vulnerability: Incomplete Blocklist Bypass in URL Preview

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L159-L193  

### Description
The `handlePreview` handler blocks requests to `localhost` and `127.0.0.1` but the blocklist is trivially incomplete. It does not block other loopback addresses (`127.0.0.2`, `[::1]`), private network ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`), or cloud metadata IPs (`169.254.169.254`).

### Exploitation Scenario
An attacker sends `GET /api/preview?target=http://[::1]:8080/admin` to access an internal service via the IPv6 loopback address. The string `::1` does not match the blocklist entries, so the request proceeds.

### Remediation Guidance
Resolve the hostname and validate the resolved IP:
```go
ips, _ := net.LookupIP(parsed.Hostname())
for _, ip := range ips {
    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
        c.JSON(403, gin.H{"error": "Blocked host"})
        return
    }
}
```

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
**Affected Lines:** L228-L255  

### Description
The `handleTestWebhook` handler retrieves a stored webhook callback URL and makes an HTTP POST to it without re-validating the destination. The registration handler only checks the URL scheme. At test time, the stored URL is used directly with `http.Client.Post`, creating a two-step SSRF.

### Exploitation Scenario
An attacker registers a webhook with `callback_url` set to `http://169.254.169.254/latest/meta-data/`. The registration succeeds because only the scheme is validated. The attacker then triggers `POST /api/webhooks/<id>/test`, causing the server to POST to the metadata endpoint.

### Remediation Guidance
Re-validate the callback URL at delivery time:
```go
parsed, _ := url.Parse(webhook.CallbackURL)
ips, _ := net.LookupIP(parsed.Hostname())
for _, ip := range ips {
    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
        c.JSON(403, gin.H{"error": "Blocked callback destination"})
        return
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans two handlers (registration and test). The scheme check during registration may give a false sense of security.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must track data flow from the webhook map (storage) to the HTTP request, requiring interprocedural analysis across two handlers.

---

## Vulnerability: Metadata Endpoint Check Bypassable via DNS Rebinding

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L257-L293  

### Description
The `handleImportConfig` handler checks whether the hostname starts with `169.254` to block cloud metadata access. This check is performed on the hostname string before DNS resolution. An attacker can use DNS rebinding where a custom domain initially resolves to a safe IP but later resolves to `169.254.169.254`.

### Exploitation Scenario
An attacker controls DNS for `evil.example.com` with a short TTL. The first lookup returns `1.2.3.4` (passing the hostname check), but when `http.Client.Get` resolves the domain, the DNS record has changed to `169.254.169.254`. The server fetches the metadata and returns it as parsed JSON.

### Remediation Guidance
Resolve the hostname before making the request and validate the resolved IP:
```go
ips, _ := net.LookupIP(parsed.Hostname())
for _, ip := range ips {
    if ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsPrivate() {
        c.JSON(403, gin.H{"error": "Blocked destination"})
        return
    }
}
```

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
**Affected Lines:** L295-L330  

### Description
The `handleProxy` handler maps known service names to internal URLs but falls back to a user-supplied `base_url` query parameter when the service is not recognized. The `base_url` is concatenated with `path` and fetched without validation, turning the proxy into an open relay.

### Exploitation Scenario
An attacker sends `GET /api/proxy?service=unknown&base_url=http://169.254.169.254&path=/latest/meta-data/` to access cloud metadata. Since `unknown` is not in the service map, the server uses the attacker-controlled `base_url`.

### Remediation Guidance
Remove the `base_url` fallback:
```go
resolvedBase, ok := serviceMap[service]
if !ok {
    c.JSON(400, gin.H{"error": "Unknown service"})
    return
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability is hidden within a legitimate service proxy pattern. The fallback to user input only occurs when the service lookup fails.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must understand the conditional logic where user-supplied `base_url` is only used as a fallback. The primary path uses a hardcoded service map.
