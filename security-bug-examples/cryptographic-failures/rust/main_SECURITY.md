# Security Companion Document: main.rs

## Vulnerability: DES Encryption in ECB Mode for Data Protection

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L103-L115  

### Description
The application uses DES in ECB mode (block-by-block encryption without chaining) to encrypt sensitive records. DES has a 56-bit key that is trivially brute-forced. ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns.

### Exploitation Scenario
An attacker who intercepts encrypted records brute-forces the 56-bit DES key using cloud GPU instances. ECB mode reveals patterns — repeated 8-byte blocks produce identical ciphertext, enabling content analysis without full decryption.

### Remediation Guidance
Replace DES/ECB with AES-256/GCM using the `aes-gcm` crate:
```rust
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap();
```

### Complexity Rationale
This is rated Obvious because the code imports the `des` crate and manually encrypts block-by-block, which is a textbook ECB implementation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match the `des` crate import and `BlockEncrypt` usage pattern.

---

## Vulnerability: Hardcoded DES Encryption Key

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L7-L7  

### Description
The DES encryption key is hardcoded as `*b"s3cr3t!!"` in a constant. Anyone with access to the source code or compiled binary can extract the key and decrypt all records.

### Exploitation Scenario
An attacker obtains the binary, uses `strings` to extract the key value, and decrypts all encrypted records stored by the application.

### Remediation Guidance
Load encryption keys from environment variables:
```rust
let key = std::env::var("ENCRYPTION_KEY").expect("key required").into_bytes();
```

### Complexity Rationale
This is rated Obvious because the key is a plaintext byte literal assigned to a named constant.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded byte arrays used with cryptographic functions.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L49-L51  

### Description
User passwords are hashed using the `md5` crate without salting. MD5 is cryptographically broken for password storage — it is fast to compute, enabling brute-force and rainbow table attacks.

### Exploitation Scenario
An attacker who gains access to user data extracts MD5 hashes and cracks them using Hashcat or rainbow tables within minutes.

### Remediation Guidance
Use bcrypt or argon2 for password hashing:
```rust
use bcrypt::{hash, verify, DEFAULT_COST};
let hashed = hash(password, DEFAULT_COST).unwrap();
```

### Complexity Rationale
This is rated Moderate because the code uses a standard hashing crate in a way that appears functional. A reviewer must know MD5 is inappropriate for password hashing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `md5::compute` usage in authentication contexts.

---

## Vulnerability: MD5 Used for Data Integrity Signatures

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L132-L134  

### Description
The `compute_signature` function uses MD5 to create integrity signatures by hashing data concatenated with a secret. MD5 is vulnerable to collision attacks, and simple concatenation is susceptible to length extension attacks.

### Exploitation Scenario
An attacker crafts an MD5 collision to produce different data with the same signature, enabling undetected tampering of encrypted records.

### Remediation Guidance
Use HMAC with SHA-256:
```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
mac.update(data.as_bytes());
hex::encode(mac.finalize().into_bytes())
```

### Complexity Rationale
This is rated Moderate because the function name suggests HMAC-like behavior but uses plain MD5 concatenation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize MD5 used for integrity verification as insecure.

---

## Vulnerability: Predictable Session Token Generation via Custom PRNG

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L66-L78  

### Description
Session tokens are generated using a custom linear congruential generator (LCG) seeded with the system time in nanoseconds. LCGs are not cryptographically secure — their output is predictable given the seed. The seed is derived from system time, which can be estimated by an attacker.

### Exploitation Scenario
An attacker who knows the approximate server startup time estimates the nanosecond seed value, reproduces the PRNG state, and generates valid session tokens to hijack user sessions.

### Remediation Guidance
Use the `rand` crate with `OsRng` for cryptographically secure token generation:
```rust
use rand::Rng;
let token: String = rand::thread_rng()
    .sample_iter(&rand::distributions::Alphanumeric)
    .take(32)
    .map(char::from)
    .collect();
```

### Complexity Rationale
This is rated Nuanced because the custom PRNG function produces tokens of reasonable length. The vulnerability lies in the predictable seed and weak LCG algorithm, requiring understanding of PRNG internals.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to recognize the custom LCG as a non-cryptographic PRNG and trace the seed to system time, which requires deep semantic analysis.

---

## Vulnerability: Predictable API Token Generation

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L80-L86  

### Description
API tokens are generated by SHA-1 hashing a predictable string `"tkn-{seq}-{timestamp}"` and truncating to 24 characters. Both the sequential counter and timestamp are predictable, making the hash output reproducible.

### Exploitation Scenario
An attacker who knows the approximate generation time and can estimate the sequence number computes the same SHA-1 hash, reproducing valid API tokens.

### Remediation Guidance
Use `OsRng` for API token generation:
```rust
use rand::RngCore;
let mut bytes = [0u8; 16];
rand::rngs::OsRng.fill_bytes(&mut bytes);
hex::encode(bytes)
```

### Complexity Rationale
This is rated Nuanced because SHA-1 hashing superficially appears secure, but hashing predictable inputs does not produce unpredictable outputs.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to analyze the entropy of the hash input to detect insufficient randomness.
