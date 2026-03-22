# Security Companion Document: app.js

## Vulnerability: Direct URL Fetch from User Input

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L77-L94  

### Description
The `/api/fetch-url` endpoint accepts a URL from the request body and passes it directly to the `fetchUrl` helper function, which uses Node.js `http`/`https` modules to make a GET request without any validation. An attacker can supply internal network addresses, cloud metadata endpoints, or localhost services.

### Exploitation Scenario
An attacker sends `POST /api/fetch-url` with `{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` to retrieve AWS IAM credentials. The server fetches the metadata service and returns the response body containing temporary access keys.

### Remediation Guidance
Validate and restrict URLs before fetching:
```javascript
const { URL } = require("url");
const dns = require("dns").promises;
const net = require("net");

async function isSafeUrl(targetUrl) {
  const parsed = new URL(targetUrl);
  const addresses = await dns.resolve4(parsed.hostname);
  for (const addr of addresses) {
    if (net.isIP(addr) && (addr.startsWith("127.") || addr.startsWith("10.") || addr.startsWith("169.254."))) {
      return false;
    }
  }
  return true;
}
```

### Complexity Rationale
This is rated Obvious because user input flows directly from `req.body.url` into `fetchUrl(url)` with zero validation. The taint path is a single step.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the direct data flow from `req.body` to `http.get`. This is a textbook SSRF pattern.

---

## Vulnerability: Incomplete Blocklist Bypass in URL Preview

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L96-L119  

### Description
The `/api/preview` endpoint blocks requests to `localhost` and `127.0.0.1` using an array includes check on the parsed hostname. This blocklist is trivially incomplete. It does not block other loopback addresses (`127.0.0.2`, `0.0.0.0`, `[::1]`), private network ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`), or cloud metadata IPs (`169.254.169.254`).

### Exploitation Scenario
An attacker sends `GET /api/preview?target=http://[::1]:3000/admin` to access an internal service via the IPv6 loopback address. The string `::1` does not match the blocklist entries, so the request proceeds.

### Remediation Guidance
Resolve the hostname to an IP address and check against all private/reserved ranges:
```javascript
const dns = require("dns").promises;
const addresses = await dns.resolve4(parsed.hostname);
for (const addr of addresses) {
  if (addr.startsWith("127.") || addr.startsWith("10.") || addr.startsWith("169.254.")) {
    return res.status(403).json({ error: "Blocked host" });
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
**Affected Lines:** L153-L189  

### Description
The `/api/webhooks/:id/test` endpoint retrieves a stored webhook callback URL and makes an HTTP POST to it without re-validating the destination. The registration endpoint only checks the URL scheme. At test time, the stored URL is used directly with `http.request`, creating a two-step SSRF.

### Exploitation Scenario
An attacker registers a webhook with `callbackUrl` set to `http://169.254.169.254/latest/meta-data/`. The registration succeeds because only the protocol scheme is validated. The attacker then triggers `POST /api/webhooks/<id>/test`, causing the server to POST to the metadata endpoint.

### Remediation Guidance
Re-validate the callback URL at delivery time:
```javascript
const parsed = new URL(webhook.callbackUrl);
const addresses = await dns.resolve4(parsed.hostname);
for (const addr of addresses) {
  if (addr.startsWith("127.") || addr.startsWith("169.254.")) {
    return res.status(403).json({ error: "Blocked callback destination" });
  }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans two endpoints (registration and test). The scheme check during registration may give a false sense of security.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must track data flow from the webhooks object (storage) to the HTTP request, requiring interprocedural analysis across two route handlers.

---

## Vulnerability: Metadata Endpoint Check Bypassable via DNS Rebinding

**CWE:** CWE-918  
**OWASP:** A10  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L191-L217  

### Description
The `/api/integrations/import` endpoint checks whether the hostname starts with `169.254` to block cloud metadata access. This check is performed on the hostname string before DNS resolution. An attacker can use DNS rebinding where a custom domain initially resolves to a safe IP but later resolves to `169.254.169.254`. The check also fails for hostnames like `metadata.internal` that resolve to the metadata IP.

### Exploitation Scenario
An attacker controls DNS for `evil.example.com` with a short TTL. The first DNS lookup returns `1.2.3.4` (passing the hostname check), but when the HTTP client resolves the domain, the DNS record has changed to `169.254.169.254`. The server fetches the metadata and returns it as parsed JSON.

### Remediation Guidance
Resolve the hostname before making the request and validate the resolved IP:
```javascript
const dns = require("dns").promises;
const addresses = await dns.resolve4(parsed.hostname);
for (const addr of addresses) {
  if (addr.startsWith("169.254.") || addr.startsWith("127.")) {
    return res.status(403).json({ error: "Blocked destination" });
  }
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
**Affected Lines:** L219-L245  

### Description
The `/api/proxy` endpoint maps known service names to internal URLs but falls back to a user-supplied `baseUrl` query parameter when the service name is not recognized. The `baseUrl` is concatenated with `path` and fetched without validation, turning the proxy into an open relay.

### Exploitation Scenario
An attacker sends `GET /api/proxy?service=unknown&baseUrl=http://169.254.169.254&path=/latest/meta-data/` to access cloud metadata. Since `unknown` is not in the service map, the server uses the attacker-controlled `baseUrl`.

### Remediation Guidance
Remove the `baseUrl` fallback:
```javascript
let resolvedBase = serviceMap[service] || "";
if (!resolvedBase) return res.status(400).json({ error: "Unknown service" });
```

### Complexity Rationale
This is rated Nuanced because the vulnerability is hidden within a legitimate service proxy pattern. The fallback to user input only occurs when the service name lookup fails.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must understand the conditional logic where user-supplied `baseUrl` is only used as a fallback. The primary path uses a hardcoded service map.
