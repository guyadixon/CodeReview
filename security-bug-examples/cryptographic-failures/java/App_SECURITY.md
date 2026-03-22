# Security Companion Document: App.java

## Vulnerability: DES Encryption in ECB Mode for Data Protection

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L91-L99  

### Description
The application uses DES with ECB mode (`DES/ECB/PKCS5Padding`) to encrypt sensitive records. DES has a 56-bit key that can be brute-forced in hours with modern hardware. ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns.

### Exploitation Scenario
An attacker who intercepts encrypted records brute-forces the 56-bit DES key using cloud GPU instances. ECB mode additionally reveals patterns — repeated plaintext blocks produce identical ciphertext, allowing the attacker to identify duplicate content without full decryption.

### Remediation Guidance
Replace DES/ECB with AES-256/GCM:
```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
```

### Complexity Rationale
This is rated Obvious because `Cipher.getInstance("DES/ECB/PKCS5Padding")` is a direct, visible call to a deprecated cipher and insecure mode.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match the `DES` and `ECB` strings in `Cipher.getInstance()` calls through simple pattern matching.

---

## Vulnerability: Hardcoded DES Encryption Key

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L19-L19  

### Description
The DES encryption key is hardcoded as `"s3cr3t!!"` directly in the source code as a static final field. Anyone with access to the source or decompiled bytecode can extract the key and decrypt all records.

### Exploitation Scenario
An attacker decompiles the JAR file, extracts the `DES_KEY` constant value `s3cr3t!!`, and uses it to decrypt any encrypted record stored by the application.

### Remediation Guidance
Load encryption keys from environment variables or a secrets manager:
```java
private static final byte[] KEY = System.getenv("ENCRYPTION_KEY").getBytes();
```

### Complexity Rationale
This is rated Obvious because the key is a plaintext string constant assigned to a clearly named static field.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded byte arrays passed to `SecretKeySpec` constructors.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L50-L58  

### Description
User passwords are hashed using `MessageDigest.getInstance("MD5")` without salting. MD5 is cryptographically broken for password storage — it is fast to compute, enabling brute-force and rainbow table attacks.

### Exploitation Scenario
An attacker who gains access to user data extracts MD5 hashes and cracks them using Hashcat or rainbow tables within minutes, recovering all user passwords.

### Remediation Guidance
Use bcrypt for password hashing:
```java
import org.mindrot.jbcrypt.BCrypt;
String hashed = BCrypt.hashpw(password, BCrypt.gensalt(12));
```

### Complexity Rationale
This is rated Moderate because the code uses the standard `MessageDigest` API in a way that appears functional. A reviewer must know MD5 is inappropriate for password hashing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `MessageDigest.getInstance("MD5")` usage through API pattern matching.

---

## Vulnerability: MD5 Used for Data Integrity Signatures

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L111-L113  

### Description
The `computeSignature` method uses MD5 to create integrity signatures by hashing data concatenated with a secret. MD5 is vulnerable to collision attacks, and simple concatenation (instead of HMAC) is susceptible to length extension attacks.

### Exploitation Scenario
An attacker crafts a collision — two different data values producing the same MD5 hash — and replaces record content while the integrity check still passes, enabling undetected data tampering.

### Remediation Guidance
Use HMAC with SHA-256:
```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
```

### Complexity Rationale
This is rated Moderate because the method name suggests HMAC-like behavior but uses plain MD5 concatenation. A reviewer must understand the difference between HMAC and hash-with-secret.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize MD5 used for integrity verification as insecure, requiring crypto-specific analysis rules.

---

## Vulnerability: Predictable Session Token Generation via Seeded PRNG

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L29-L29, L70-L84  

### Description
Session tokens are generated using `java.util.Random` seeded with `System.currentTimeMillis() / 1000`. `java.util.Random` is not cryptographically secure, and the seed is derived from the current Unix timestamp (second precision), making tokens predictable if the attacker knows the approximate login time.

### Exploitation Scenario
An attacker observes a login occurring at a known time, seeds a `Random` instance with the same timestamp value, and generates the identical 32-character hex token to hijack the session.

### Remediation Guidance
Use `java.security.SecureRandom` for token generation:
```java
SecureRandom secureRng = new SecureRandom();
byte[] tokenBytes = new byte[32];
secureRng.nextBytes(tokenBytes);
```

### Complexity Rationale
This is rated Nuanced because the code generates tokens of reasonable length using a standard Random class. The vulnerability lies in the predictable seed and the non-cryptographic nature of the PRNG.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to trace the seed to `System.currentTimeMillis()`, understand that `java.util.Random` with a predictable seed produces predictable output, and connect this to session token generation.

---

## Vulnerability: Predictable API Token Generation

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L115-L119  

### Description
API tokens are generated by SHA-1 hashing a predictable string `"tkn-{seq}-{timestamp}"` and truncating to 24 characters. Both the sequential counter and timestamp are predictable, so the hash output is reproducible by anyone who can estimate these values.

### Exploitation Scenario
An attacker who knows the approximate token generation time and can estimate the sequence number computes the same SHA-1 hash, reproducing valid API tokens to gain unauthorized access.

### Remediation Guidance
Use `SecureRandom` for API token generation:
```java
SecureRandom sr = new SecureRandom();
byte[] bytes = new byte[16];
sr.nextBytes(bytes);
return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
```

### Complexity Rationale
This is rated Nuanced because SHA-1 hashing superficially appears secure. The vulnerability is that hashing predictable inputs does not produce unpredictable outputs.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to analyze the entropy of the hash input, recognizing that a sequential counter and timestamp provide insufficient randomness.
