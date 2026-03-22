# Security Companion Document: main.rs

## Vulnerability: Outdated Actix-web 3.3.3 with Known Security Issues

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L1  

### Description
The application uses actix-web 3.3.3 (pinned in Cargo.toml), which is a major version behind the current release. Actix-web 3.x has known security vulnerabilities and is no longer maintained. The 4.x series includes significant security improvements including better request size limits, improved header parsing, and fixes for denial-of-service vectors.

### Exploitation Scenario
An attacker exploits known vulnerabilities in actix-web 3.x such as header parsing issues or request handling flaws to cause denial of service or bypass security controls. The unmaintained status means no further patches will be released for newly discovered issues.

### Remediation Guidance
Update to actix-web 4.x in Cargo.toml:
```toml
[dependencies]
actix-web = "4.4.0"
```
Note: The API has breaking changes between 3.x and 4.x that require code updates.

### Complexity Rationale
This is rated Obvious because the major version gap (3.x vs 4.x) is immediately visible in Cargo.toml and actix-web 3.x end-of-life is well-documented.

### Detection Difficulty Rationale
This is rated Easily_Detectable because cargo-audit and dependency scanners directly flag unmaintained and outdated actix-web versions.

---

## Vulnerability: Outdated Serde 1.0.130 Missing Security Patches

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L2  

### Description
The application pins serde to version 1.0.130, which is significantly behind the current release. While serde is generally safe, older versions may have edge cases in deserialization handling that have been fixed in later releases. The application deserializes user-supplied JSON for orders and inventory imports.

### Exploitation Scenario
An attacker crafts JSON payloads that exploit edge cases in serde 1.0.130's deserialization logic, potentially causing panics or unexpected behavior when processing order creation or inventory import requests.

### Remediation Guidance
Update serde in Cargo.toml:
```toml
serde = { version = "1.0.193", features = ["derive"] }
```

### Complexity Rationale
This is rated Moderate because serde vulnerabilities are less dramatic than framework-level issues, but the significant version gap means many bug fixes and hardening improvements are missing.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because cargo-audit may not flag serde as having critical CVEs, but the version gap is significant enough that manual review should catch it.

---

## Vulnerability: Outdated serde_json 1.0.68 with Parsing Edge Cases

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L3  

### Description
The application uses serde_json 1.0.68, which is significantly behind the current release. Older versions have known issues with number parsing precision, deeply nested structure handling, and other edge cases that can lead to denial of service or unexpected behavior.

### Exploitation Scenario
An attacker sends deeply nested JSON structures or specially crafted numeric values to the inventory import endpoint that exploit parsing edge cases in serde_json 1.0.68, causing stack overflow or excessive memory consumption leading to denial of service.

### Remediation Guidance
Update serde_json in Cargo.toml:
```toml
serde_json = "1.0.108"
```

### Complexity Rationale
This is rated Nuanced because serde_json parsing edge cases are subtle and require deep understanding of JSON parsing internals and how specific version differences affect behavior.

### Detection Difficulty Rationale
This is rated Likely_Missed because serde_json is rarely flagged by security scanners for version-specific issues, and the vulnerabilities are in edge cases rather than well-known CVEs.
