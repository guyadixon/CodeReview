# Security Companion Document: app.py

## Vulnerability: DES Encryption Used for Data Protection

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L70-L74  

### Description
The application uses DES (Data Encryption Standard) in ECB mode to encrypt sensitive records. DES has a 56-bit key length that is trivially brute-forced with modern hardware. ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns.

### Exploitation Scenario
An attacker who intercepts encrypted records can brute-force the 56-bit DES key using commodity hardware or cloud instances in hours. Additionally, ECB mode reveals patterns — identical plaintext blocks produce identical ciphertext blocks, allowing the attacker to detect repeated content without decryption.

### Remediation Guidance
Replace DES/ECB with AES-256 in GCM mode:
```python
from Crypto.Cipher import AES
import os

def encrypt_record(plaintext):
    key = os.environ.get("ENCRYPTION_KEY").encode()  # 32 bytes for AES-256
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
```

### Complexity Rationale
This is rated Obvious because `DES.new(ENCRYPTION_KEY, DES.MODE_ECB)` is a direct, visible call to a deprecated cipher and insecure mode. Any reviewer familiar with cryptography will immediately recognize the issue.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match the `DES` import and `MODE_ECB` constant through simple pattern matching on known-insecure cryptographic APIs.

---

## Vulnerability: Hardcoded Encryption Key

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L11-L11  

### Description
The DES encryption key is hardcoded as `b"s3cr3t!!"` directly in the source code. Any person with access to the source code or compiled artifact can extract the key and decrypt all records.

### Exploitation Scenario
An attacker obtains the source code through a repository leak or reverse engineering. They extract the key `s3cr3t!!` and use it to decrypt any encrypted record stored by the application, compromising all protected data.

### Remediation Guidance
Load encryption keys from environment variables or a secrets manager:
```python
import os
ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"].encode()
```

### Complexity Rationale
This is rated Obvious because the key is a plaintext byte string assigned to a clearly named constant at module level.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded byte strings passed to cryptographic constructors through pattern matching on variable names and crypto API arguments.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L27-L38  

### Description
User passwords are hashed using `hashlib.md5()` without salting. MD5 is cryptographically broken — it is fast to compute, enabling brute-force and rainbow table attacks. The lack of per-user salts means identical passwords produce identical hashes.

### Exploitation Scenario
An attacker who gains access to the user data extracts MD5 hashes. Using precomputed rainbow tables or GPU-accelerated tools like Hashcat, they crack all passwords in minutes, recovering credentials like "admin2024!" and "diana_w99".

### Remediation Guidance
Use bcrypt or argon2 for password hashing:
```python
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
```

### Complexity Rationale
This is rated Moderate because the code uses the standard `hashlib` library in a way that appears functional. A reviewer must know that MD5 is inappropriate for password hashing specifically.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `hashlib.md5` usage in authentication contexts through API pattern matching.

---

## Vulnerability: MD5 Used for Data Integrity Signatures

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L84-L85  

### Description
The `compute_signature` function uses MD5 to create integrity signatures for encrypted records by concatenating the data with a secret. MD5 is vulnerable to collision attacks, allowing an attacker to craft different data that produces the same signature, defeating integrity verification.

### Exploitation Scenario
An attacker who can modify encrypted records crafts a collision — two different plaintext values that produce the same MD5 signature. They replace the encrypted content while the signature verification still passes, allowing undetected data tampering.

### Remediation Guidance
Use HMAC with SHA-256 for integrity signatures:
```python
import hmac, hashlib

def compute_signature(data):
    return hmac.new(HMAC_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
```

### Complexity Rationale
This is rated Moderate because the function name suggests HMAC-like behavior but actually uses plain MD5 concatenation. A reviewer must understand the difference between HMAC and simple hash-with-secret.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that MD5 used for integrity verification (not just hashing) is insecure. Tools with crypto-specific rules may flag this, but generic tools may miss the context.

---

## Vulnerability: Predictable Session Token Generation via Seeded PRNG

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L44-L49  

### Description
Session tokens are generated using Python's `random` module seeded with `int(time.time()) + user_id`. The `random` module uses a Mersenne Twister PRNG that is not cryptographically secure. Since the seed is derived from the current Unix timestamp plus a small user ID, an attacker who knows the approximate login time can reproduce the exact token.

### Exploitation Scenario
An attacker monitors when a target user logs in (within a one-second window). They compute `int(time.time()) + user_id` for that second, seed Python's `random` module identically, and generate the same 32-character token. They then use this token to hijack the user's session.

### Remediation Guidance
Use `secrets` module for cryptographically secure token generation:
```python
import secrets

def generate_session_token(user_id):
    token = secrets.token_hex(32)
    SESSIONS[token] = {"user_id": user_id, "created": time.time()}
    return token
```

### Complexity Rationale
This is rated Nuanced because the code appears to generate random tokens of reasonable length. The vulnerability lies in the predictability of the seed value, which requires understanding PRNG internals and the weakness of time-based seeding.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to trace the seed value to `time.time()`, understand that `random.seed()` with a predictable value makes all subsequent outputs predictable, and recognize this in a session token context. Most tools flag `random` usage but miss the seed predictability chain.

---

## Vulnerability: Predictable API Token Generation

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L88-L93  

### Description
API tokens are generated by hashing a predictable string `"token-{counter}-{timestamp}"` with SHA-1 and truncating to 24 characters. Both the counter and timestamp are predictable — the counter increments sequentially and the timestamp is the current Unix time. An attacker who knows the approximate generation time and can estimate the counter value can reproduce valid API tokens.

### Exploitation Scenario
An attacker who knows the approximate token generation time and can estimate the sequence counter computes the same SHA-1 hash, reproducing valid API tokens to gain unauthorized access to protected resources.

### Remediation Guidance
Use cryptographically secure random token generation:
```python
import secrets

def generate_api_token():
    return secrets.token_hex(16)
```

### Complexity Rationale
This is rated Nuanced because the function uses SHA-1 hashing which superficially appears secure. The vulnerability is that hashing predictable inputs does not produce unpredictable outputs — the entropy comes from the input, not the hash function.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to analyze the entropy of the hash input, recognizing that a sequential counter and timestamp provide insufficient randomness. This requires semantic understanding beyond pattern matching.
