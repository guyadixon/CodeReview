# Security Companion Document: app.js

## Vulnerability: DES Encryption in ECB Mode for Data Protection

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L52-L58  

### Description
The application uses DES in ECB mode (`des-ecb`) via Node.js `crypto` module to encrypt sensitive records. DES has a 56-bit key that is trivially brute-forced. ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns.

### Exploitation Scenario
An attacker who intercepts encrypted records brute-forces the 56-bit DES key. ECB mode reveals patterns — repeated plaintext blocks produce identical ciphertext, enabling content analysis without full decryption.

### Remediation Guidance
Replace DES/ECB with AES-256/GCM:
```javascript
const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
let encrypted = cipher.update(plaintext, "utf8", "base64");
encrypted += cipher.final("base64");
const tag = cipher.getAuthTag();
```

### Complexity Rationale
This is rated Obvious because `crypto.createCipheriv("des-ecb", ...)` is a direct, visible call to a deprecated cipher and insecure mode.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match the `des-ecb` string in `createCipheriv` calls through simple pattern matching.

---

## Vulnerability: Hardcoded DES Encryption Key

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L6-L6  

### Description
The DES encryption key is hardcoded as `Buffer.from("s3cr3t!!", "utf8")` directly in the source code. Anyone with access to the source can extract the key and decrypt all records.

### Exploitation Scenario
An attacker reads the source code, extracts the key value `s3cr3t!!`, and decrypts any encrypted record stored by the application.

### Remediation Guidance
Load encryption keys from environment variables:
```javascript
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, "hex");
```

### Complexity Rationale
This is rated Obvious because the key is a plaintext string constant assigned to a clearly named variable.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded Buffer values passed to cryptographic functions.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L19-L29  

### Description
User passwords are hashed using `crypto.createHash("md5")` without salting. MD5 is cryptographically broken for password storage — it is fast to compute, enabling brute-force and rainbow table attacks.

### Exploitation Scenario
An attacker who gains access to user data extracts MD5 hashes and cracks them using Hashcat or rainbow tables within minutes.

### Remediation Guidance
Use bcrypt for password hashing:
```javascript
const bcrypt = require("bcrypt");
const hash = await bcrypt.hash(password, 12);
```

### Complexity Rationale
This is rated Moderate because the code uses the standard `crypto` module in a way that appears functional. A reviewer must know MD5 is inappropriate for password hashing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `createHash("md5")` usage in authentication contexts.

---

## Vulnerability: MD5 Used for Data Integrity Signatures

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L68-L70  

### Description
The `computeSignature` function uses MD5 to create integrity signatures by hashing data concatenated with a secret. MD5 is vulnerable to collision attacks, and simple concatenation is susceptible to length extension attacks.

### Exploitation Scenario
An attacker crafts an MD5 collision to produce different data with the same signature, enabling undetected tampering of encrypted records.

### Remediation Guidance
Use HMAC with SHA-256:
```javascript
const signature = crypto.createHmac("sha256", secret).update(data).digest("hex");
```

### Complexity Rationale
This is rated Moderate because the function name and the `SIGNING_SECRET` constant suggest HMAC-like behavior, but the implementation uses plain MD5 concatenation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize MD5 used for integrity verification as insecure, requiring crypto-specific rules.

---

## Vulnerability: Predictable Session Token Generation via LCG PRNG

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L34-L45  

### Description
Session tokens are generated using a custom linear congruential generator (LCG) seeded with `userId * 1000 + Math.floor(Date.now() / 1000)`. LCGs are not cryptographically secure, and the seed is derived from the user ID and current Unix timestamp, both of which are predictable.

### Exploitation Scenario
An attacker who knows the target user's ID and approximate login time computes the same seed, runs the same LCG algorithm, and generates the identical 32-character token to hijack the session.

### Remediation Guidance
Use `crypto.randomBytes` for cryptographically secure token generation:
```javascript
const token = crypto.randomBytes(32).toString("hex");
```

### Complexity Rationale
This is rated Nuanced because the code generates tokens of reasonable length using what appears to be a random process. The vulnerability lies in the predictable seed and weak LCG algorithm, requiring understanding of PRNG internals.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to recognize the custom LCG as non-cryptographic and trace the seed to predictable values. Most tools flag `Math.random()` but may miss custom PRNG implementations.

---

## Vulnerability: Predictable API Token Generation

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L72-L77  

### Description
API tokens are generated by SHA-1 hashing a predictable string `` `tkn-${tokenSeq}-${ts}` `` and truncating to 24 characters. Both the sequential counter and timestamp are predictable, making the hash output reproducible.

### Exploitation Scenario
An attacker who knows the approximate generation time and can estimate the sequence number computes the same SHA-1 hash, reproducing valid API tokens.

### Remediation Guidance
Use `crypto.randomBytes` for API token generation:
```javascript
const token = crypto.randomBytes(16).toString("hex");
```

### Complexity Rationale
This is rated Nuanced because SHA-1 hashing superficially appears secure, but hashing predictable inputs does not produce unpredictable outputs.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to analyze the entropy of the hash input to detect insufficient randomness.
