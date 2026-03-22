# Security Companion Document: app.py

## Vulnerability: Direct URL Fetch from User Input

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L63-L80  

### Description
The `/api/fetch-url` endpoint accepts a URL from the request body and passes it directly to `urllib.request.urlopen` without any validation or restriction. An attacker can supply any URL, including internal network addresses, cloud metadata endpoints, and localhost services, causing the server to make requests on their behalf.

### Exploitation Scenario
An attacker sends `POST /api/fetch-url` with `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` to retrieve AWS IAM credentials from the instance metadata service. The server fetches the URL and returns the response body containing temporary access keys, enabling the attacker to escalate privileges within the cloud environment.

### Remediation Guidance
Validate and restrict URLs before fetching:
```python
import ipaddress

def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        pass  # hostname is not an IP, resolve and check
    return True
```

### Complexity Rationale
This is rated Obvious because user input flows directly into a URL-fetching function with zero validation. The taint path from `data.get("url")` to `urlopen(url)` is a single step with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the direct data flow from user input (`request.get_json()`) to a network request function (`urlopen`). This is a textbook SSRF pattern that all major SAST tools flag.

---

## Vulnerability: Incomplete Blocklist Bypass in URL Preview

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L83-L107  

### Description
The `/api/preview` endpoint attempts to block requests to `localhost` and `127.0.0.1` but the blocklist is trivially incomplete. It does not block other loopback representations (`127.0.0.2`, `0.0.0.0`, `[::1]`, `0x7f000001`), private network ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`), or cloud metadata IPs (`169.254.169.254`). An attacker can bypass the check using any alternative representation.

### Exploitation Scenario
An attacker sends `GET /api/preview?target=http://0x7f000001:8080/admin` to access an internal admin panel. The hex-encoded IP `0x7f000001` resolves to `127.0.0.1` but does not match the string comparison in the blocklist, so the request proceeds and the server fetches the internal resource.

### Remediation Guidance
Resolve the hostname to an IP address and check against all private/reserved ranges:
```python
import ipaddress, socket

def is_blocked_host(hostname):
    try:
        resolved = socket.getaddrinfo(hostname, None)
        for _, _, _, _, addr in resolved:
            ip = ipaddress.ip_address(addr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return True
    except socket.gaierror:
        return True
    return False
```

### Complexity Rationale
This is rated Moderate because a blocklist is present, which may satisfy a cursory review. The reviewer must recognize that the blocklist is incomplete and understand the many alternative representations of internal addresses.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools can detect the URL fetch but evaluating the completeness of a blocklist requires understanding of IP address representations and network ranges, which depends on the tool's rule sophistication.

---

## Vulnerability: Webhook Callback Without Re-validation

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L133-L155  

### Description
The `/api/webhooks/<id>/test` endpoint retrieves a previously registered webhook's callback URL from storage and makes an HTTP request to it without re-validating the URL. While the registration endpoint checks that the URL uses HTTP(S), it does not block internal addresses. At test time, the stored URL is used directly, creating a two-step SSRF where the attacker first registers a malicious callback URL and then triggers it.

### Exploitation Scenario
An attacker registers a webhook with `callback_url` set to `http://169.254.169.254/latest/meta-data/`. The registration succeeds because only the protocol scheme is validated. The attacker then calls `POST /api/webhooks/<id>/test`, causing the server to POST to the metadata endpoint. The response status confirms reachability, and the attacker can iterate to extract metadata values.

### Remediation Guidance
Re-validate the callback URL at delivery time and apply the same restrictions as for direct URL fetches:
```python
parsed = urllib.parse.urlparse(webhook["callback_url"])
if is_blocked_host(parsed.hostname):
    return jsonify({"error": "Blocked callback destination"}), 403
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans two endpoints (registration and test), requiring the reviewer to trace the data flow across both. The registration endpoint's scheme check may give a false sense of security.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must track data flow from storage (the webhook registry) to the network request, which requires interprocedural analysis across two separate request handlers.

---

## Vulnerability: Metadata Endpoint Check Bypassable via DNS Rebinding

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L158-L185  

### Description
The `/api/integrations/import` endpoint checks whether the hostname starts with `169.254` to block cloud metadata access. However, this check is performed on the hostname string before DNS resolution. An attacker can use a DNS rebinding attack where a custom domain initially resolves to a safe IP during validation but resolves to `169.254.169.254` when the actual HTTP request is made. The check also fails for hostnames like `metadata.internal` that resolve to the metadata IP.

### Exploitation Scenario
An attacker controls a DNS server for `evil.example.com` configured with a short TTL. The first DNS lookup returns `1.2.3.4` (passing the hostname check), but by the time `urlopen` resolves the domain, the DNS record has changed to `169.254.169.254`. The server fetches the cloud metadata and returns it as a parsed JSON configuration.

### Remediation Guidance
Resolve the hostname to an IP address before making the request and validate the resolved IP:
```python
import socket, ipaddress

resolved = socket.getaddrinfo(parsed.hostname, None)
for _, _, _, _, addr in resolved:
    ip = ipaddress.ip_address(addr[0])
    if ip.is_link_local or ip.is_private or ip.is_loopback:
        return jsonify({"error": "Blocked destination"}), 403
```

### Complexity Rationale
This is rated Nuanced because a metadata protection check is present and appears functional at first glance. Understanding the bypass requires knowledge of DNS rebinding attacks and the TOCTOU gap between hostname validation and actual DNS resolution during the HTTP request.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools generally cannot detect DNS rebinding vulnerabilities. The tool sees a hostname check and a blocked string, which appears to be a valid mitigation. Identifying the TOCTOU gap requires understanding of DNS resolution timing.

---

## Vulnerability: Service Proxy with Arbitrary base_url Fallback

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L188-L213  

### Description
The `/api/proxy` endpoint maps known service names to internal URLs but falls back to a user-supplied `base_url` parameter when the service name is not recognized. The `base_url` is concatenated with a `path` parameter and fetched without any validation. An attacker can supply any arbitrary URL as the base, effectively turning the proxy into an open relay for SSRF.

### Exploitation Scenario
An attacker sends `GET /api/proxy?service=unknown&base_url=http://169.254.169.254&path=/latest/meta-data/iam/security-credentials/` to access cloud metadata through the proxy. Since `unknown` is not in the service map, the server uses the attacker-controlled `base_url`, constructs the full URL, and fetches the metadata endpoint.

### Remediation Guidance
Remove the `base_url` fallback entirely or restrict it to a predefined allowlist:
```python
base_url = service_map.get(service, "")
if not base_url:
    return jsonify({"error": "Unknown service"}), 400
# Never accept user-supplied base URLs
```

### Complexity Rationale
This is rated Nuanced because the vulnerability is hidden within a legitimate service proxy pattern. The fallback to user input only occurs when the service name lookup fails, which is a secondary code path that may be overlooked during review. The service map gives a false impression that only known services are proxied.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must understand the conditional logic where the user-supplied `base_url` is only used as a fallback. The primary code path uses a hardcoded service map, which appears safe. Detecting the fallback path requires understanding the control flow and recognizing that the `base_url` parameter reaches the network request only in the else branch.
