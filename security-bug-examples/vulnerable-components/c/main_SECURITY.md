# Security Companion Document: main.c

## Vulnerability: Outdated libmicrohttpd with Known Vulnerabilities

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L4  

### Description
The application links against libmicrohttpd, and the Makefile does not specify a minimum version. Older versions of libmicrohttpd have known vulnerabilities including denial-of-service issues, improper request parsing, and memory handling bugs. System package managers may provide outdated versions with unpatched CVEs.

### Exploitation Scenario
An attacker sends crafted HTTP requests that exploit known parsing vulnerabilities in an outdated libmicrohttpd version, causing buffer overflows or denial of service. The specific exploit depends on which version is installed on the target system.

### Remediation Guidance
Ensure libmicrohttpd 0.9.75+ is installed and add version checking:
```c
#if MHD_VERSION < 0x00097500
#error "libmicrohttpd 0.9.75 or later required"
#endif
```
Or use pkg-config to enforce minimum version in the Makefile:
```makefile
CFLAGS += $(shell pkg-config --cflags libmicrohttpd >= 0.9.75)
```

### Complexity Rationale
This is rated Moderate because the vulnerability depends on the system-installed library version rather than a pinned version in a manifest. A reviewer must check the system package version against known CVEs.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must analyze the Makefile linkage and correlate with system library versions, which requires environment-aware scanning.

---

## Vulnerability: Outdated libcurl Dependency with Multiple CVEs

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L5  

### Description
The application includes `curl/curl.h` and links against libcurl. The Makefile links with `-lcurl` without version constraints. Older libcurl versions have numerous CVEs including buffer overflows, credential leakage, and TLS verification bypasses. The application initializes curl globally, making all curl-related vulnerabilities potentially exploitable.

### Exploitation Scenario
An attacker exploits known libcurl vulnerabilities such as CVE-2023-38545 (SOCKS5 heap buffer overflow) or CVE-2023-38546 (cookie injection) if the system has an outdated libcurl version. The global curl initialization at line 233 makes the application susceptible to any curl-level vulnerability.

### Remediation Guidance
Enforce minimum libcurl version in the Makefile:
```makefile
LDFLAGS = -lmicrohttpd -ljansson
LDFLAGS += $(shell curl-config --libs)
CFLAGS += $(shell curl-config --cflags)
```
Add runtime version check:
```c
curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
```

### Complexity Rationale
This is rated Obvious because libcurl is one of the most widely tracked C libraries for security vulnerabilities, and the `-lcurl` linkage is directly visible in the Makefile.

### Detection Difficulty Rationale
This is rated Easily_Detectable because dependency scanners and system package auditors flag outdated libcurl versions with known CVEs.

---

## Vulnerability: Outdated Jansson Library Without Version Pinning

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L6  

### Description
The application uses the Jansson JSON library (linked via `-ljansson`) without version constraints. Older Jansson versions have known issues with number parsing precision, memory handling, and deeply nested object processing that can lead to denial of service or unexpected behavior.

### Exploitation Scenario
An attacker sends crafted JSON payloads with deeply nested structures or extreme numeric values to the order creation endpoint. An outdated Jansson version processes these without proper limits, causing stack overflow or excessive memory allocation leading to denial of service.

### Remediation Guidance
Add version checking in the source code:
```c
#if JANSSON_VERSION_HEX < 0x020E00
#error "Jansson 2.14 or later required"
#endif
```

### Complexity Rationale
This is rated Nuanced because Jansson is a less commonly audited library compared to curl or OpenSSL. The vulnerabilities are in edge cases of JSON parsing rather than well-publicized CVEs, requiring deep knowledge of the library's history.

### Detection Difficulty Rationale
This is rated Likely_Missed because most SAST tools do not have specific rules for Jansson version vulnerabilities, and the library is linked dynamically without version information in the source code.

---

## Vulnerability: No Compiler Security Hardening Flags

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L1-L3  

### Description
The Makefile compiles with `-Wall -Wextra -std=c11` but omits critical security hardening flags such as `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`, and `-Wformat-security`. Without these flags, the compiled binary lacks stack canaries, buffer overflow detection, and position-independent execution, making exploitation of any memory corruption vulnerability significantly easier.

### Exploitation Scenario
An attacker discovers a buffer overflow in the application's request handling. Without stack protector canaries and FORTIFY_SOURCE, the attacker can reliably exploit the overflow to achieve code execution, whereas hardened binaries would detect and abort on stack corruption.

### Remediation Guidance
Add security hardening flags to the Makefile:
```makefile
CFLAGS = -Wall -Wextra -std=c11 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wformat-security
LDFLAGS = -lmicrohttpd -lcurl -ljansson -pie -Wl,-z,relro,-z,now
```

### Complexity Rationale
This is rated Moderate because the absence of security flags requires understanding compiler hardening options and their role in defense-in-depth. The Makefile must be reviewed alongside the source code.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools that analyze build configurations can detect missing hardening flags, but many source-only scanners do not examine Makefiles.
