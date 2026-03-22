# Security Companion Document: app.js

## Vulnerability: Outdated Express 4.17.1 with Known Vulnerabilities

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L1  

### Description
The application uses Express 4.17.1 (pinned in package.json), which has known security vulnerabilities including open redirect and other issues patched in later versions. Express is the core HTTP framework, so its vulnerabilities affect all request handling.

### Exploitation Scenario
An attacker exploits known vulnerabilities in Express 4.17.1 such as open redirect issues to redirect users to malicious sites, or leverages other patched vulnerabilities to manipulate request handling.

### Remediation Guidance
Update Express in package.json:
```json
"express": "^4.18.2"
```

### Complexity Rationale
This is rated Obvious because the outdated version is directly visible in package.json and Express is one of the most widely tracked npm packages.

### Detection Difficulty Rationale
This is rated Easily_Detectable because npm audit and dependency scanners directly flag outdated Express versions.

---

## Vulnerability: Lodash 4.17.20 with Prototype Pollution

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L2, L101  

### Description
The application uses lodash 4.17.20, which is vulnerable to CVE-2021-23337 (command injection via template) and prototype pollution issues. The code uses `_.merge()` in the inventory import endpoint, which is a known vector for prototype pollution attacks in vulnerable lodash versions.

### Exploitation Scenario
An attacker sends a crafted payload to `/api/inventory/import` containing `__proto__` properties. The `_.merge()` call at line 101 merges these properties into the product objects, polluting the Object prototype and affecting all subsequent object operations in the application.

### Remediation Guidance
Update lodash in package.json:
```json
"lodash": "^4.17.21"
```
Also consider using native Object methods instead of lodash merge for untrusted input.

### Complexity Rationale
This is rated Moderate because prototype pollution via lodash merge requires understanding JavaScript's prototype chain and how merge operations can modify inherited properties.

### Detection Difficulty Rationale
This is rated Easily_Detectable because lodash prototype pollution is one of the most commonly flagged npm vulnerabilities by audit tools.

---

## Vulnerability: Outdated Axios 0.21.1 with SSRF and Header Leakage

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L6, L117  

### Description
The application uses axios 0.21.1, which has known vulnerabilities including CVE-2023-45857 (XSRF token exposure) and server-side request forgery issues. The application uses axios for warehouse sync with a user-controllable endpoint URL.

### Exploitation Scenario
An attacker exploits the outdated axios version's XSRF token handling to capture authentication tokens during the warehouse sync operation, or leverages known SSRF vulnerabilities to make requests to internal services.

### Remediation Guidance
Update axios in package.json:
```json
"axios": "^1.6.0"
```

### Complexity Rationale
This is rated Obvious because the outdated version is directly visible in package.json and axios CVEs are well-documented.

### Detection Difficulty Rationale
This is rated Easily_Detectable because npm audit directly flags outdated axios versions with known CVEs.

---

## Vulnerability: EJS 3.1.5 with Server-Side Template Injection

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L4, L108-L113  

### Description
The application uses ejs 3.1.5, which has known vulnerabilities including CVE-2022-29078 (server-side template injection). The code passes user-controlled template strings directly to `ejs.render()` for product label generation, making the vulnerable version directly exploitable.

### Exploitation Scenario
An attacker sends a request to `/api/products/1/label?template=<%%25= global.process.mainModule.require('child_process').execSync('id') %25>`. The outdated EJS version processes the template injection, executing arbitrary commands on the server.

### Remediation Guidance
Update EJS and avoid rendering user-controlled templates:
```json
"ejs": "^3.1.9"
```
Do not pass user input as template strings to ejs.render().

### Complexity Rationale
This is rated Nuanced because the vulnerability requires understanding that EJS template injection in older versions allows breaking out of the template sandbox, and the user-controlled template parameter makes it directly exploitable.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools may not correlate the EJS version with the user-controlled template string passed to ejs.render(). The vulnerability requires both version analysis and data flow tracking.

---

## Vulnerability: Marked 2.0.0 with ReDoS and XSS Vulnerabilities

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L5, L127  

### Description
The application uses marked 2.0.0, which has known vulnerabilities including ReDoS (Regular Expression Denial of Service) and XSS issues. The code uses `marked.parse()` with user-controlled markdown input for product descriptions, making both vulnerability types exploitable.

### Exploitation Scenario
An attacker sends a crafted markdown string via the `/api/products/1/description?md=` parameter that triggers catastrophic backtracking in marked's regex patterns, causing the server to hang (ReDoS). Alternatively, the attacker injects HTML/JavaScript through markdown that is not properly sanitized.

### Remediation Guidance
Update marked in package.json:
```json
"marked": "^9.0.0"
```
Also enable sanitization options in marked configuration.

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that markdown parsers can be vectors for both ReDoS and XSS, and that the user-controlled input flows directly to the parser.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must correlate the marked version with the user-controlled input flowing to marked.parse() to determine exploitability.
