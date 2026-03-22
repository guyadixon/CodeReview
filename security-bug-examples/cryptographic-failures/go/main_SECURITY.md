# Security Companion Document: main.go

## Vulnerability: DES Encryption in ECB Mode for Data Protection

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L92-L103  

### Description
The application uses DES in ECB mode (manual block-by-block encryption without chaining) to encrypt sensitive records. DES has a 56-bit key that is trivially brute-forced. ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns.

### Exploitation Scenario
An attacker who intercepts encrypted records brute-forces the 56-bit DES key. ECB mode additionally reveals patterns — repeated 8-byte blocks in the plaintext produce identical ciphertext blocks, allowing content analysis without full decryption.

### Remediation Guidance
Replace DES/ECB with AES-256/GCM:
```go
import "crypto/aes"
import "crypto/cipher"

block, _ := aes.NewCipher(aesKey)
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
io.ReadFull(rand.Reader, nonce)
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
```

### Complexity Rationale
This is rated Obvious because the code imports `crypto/des` and manually encrypts block-by-block without any chaining mode, which is a textbook ECB implementation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can match the `crypto/des` import and the block-by-block encryption pattern.

---

## Vulnerability: Hardcoded DES Encryption Key

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L21-L21  

### Description
The DES encryption key is hardcoded as `[]byte("s3cr3t!!")` at package level. Anyone with access to the source code or compiled binary can extract the key and decrypt all records.

### Exploitation Scenario
An attacker obtains the binary, uses `strings` or a Go decompiler to extract the key value, and decrypts all encrypted records stored by the application.

### Remediation Guidance
Load encryption keys from environment variables:
```go
var desKey = []byte(os.Getenv("ENCRYPTION_KEY"))
```

### Complexity Rationale
This is rated Obvious because the key is a plaintext byte slice assigned to a package-level variable.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded byte slices used with cryptographic functions.

---

## Vulnerability: MD5 Used for Password Hashing

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L64-L67  

### Description
User passwords are hashed using `crypto/md5` without salting. MD5 is cryptographically broken for password storage — it is fast to compute, enabling brute-force and rainbow table attacks.

### Exploitation Scenario
An attacker who gains access to user data extracts MD5 hashes and cracks them using Hashcat or rainbow tables within minutes.

### Remediation Guidance
Use bcrypt for password hashing:
```go
import "golang.org/x/crypto/bcrypt"
hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
```

### Complexity Rationale
This is rated Moderate because the code uses the standard `crypto/md5` package in a way that appears functional. A reviewer must know MD5 is inappropriate for password hashing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `crypto/md5` usage in authentication contexts.

---

## Vulnerability: MD5 Used for Data Integrity Signatures

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L121-L123  

### Description
The `computeSignature` function uses MD5 to create integrity signatures by hashing data concatenated with a secret. MD5 is vulnerable to collision attacks, and simple concatenation is susceptible to length extension attacks.

### Exploitation Scenario
An attacker crafts an MD5 collision to produce different data with the same signature, enabling undetected tampering of encrypted records.

### Remediation Guidance
Use HMAC with SHA-256:
```go
import "crypto/hmac"
import "crypto/sha256"
mac := hmac.New(sha256.New, []byte(secret))
mac.Write([]byte(data))
signature := hex.EncodeToString(mac.Sum(nil))
```

### Complexity Rationale
This is rated Moderate because the function name suggests HMAC-like behavior but uses plain MD5 concatenation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize MD5 used for integrity verification as insecure, requiring crypto-specific rules.

---

## Vulnerability: Predictable Session Token Generation via Weak PRNG

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L125-L136  

### Description
Session tokens are generated using `math/rand` seeded with `time.Now().Unix()`. The `math/rand` package is not cryptographically secure, and the seed is the current Unix timestamp (second precision). An attacker who knows the approximate login time can reproduce the exact token.

### Exploitation Scenario
An attacker observes a login at a known time, seeds `math/rand` with the same Unix timestamp, and generates the identical 32-character token to hijack the session.

### Remediation Guidance
Use `crypto/rand` for token generation:
```go
import "crypto/rand"
import "encoding/hex"
b := make([]byte, 32)
crypto_rand.Read(b)
token := hex.EncodeToString(b)
```

### Complexity Rationale
This is rated Nuanced because the code generates tokens of reasonable length using a standard random package. The vulnerability lies in the predictable seed and non-cryptographic PRNG.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to trace the seed to `time.Now().Unix()`, understand that `math/rand` with a predictable seed produces predictable output, and connect this to session token generation.

---

## Vulnerability: Predictable API Token Generation

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L138-L143  

### Description
API tokens are generated by SHA-1 hashing a predictable string `"tkn-{seq}-{timestamp}"` and truncating to 24 characters. Both the sequential counter and timestamp are predictable, making the hash output reproducible.

### Exploitation Scenario
An attacker who knows the approximate generation time and can estimate the sequence number computes the same SHA-1 hash, reproducing valid API tokens.

### Remediation Guidance
Use `crypto/rand` for API token generation:
```go
import "crypto/rand"
b := make([]byte, 16)
crypto_rand.Read(b)
return hex.EncodeToString(b)
```

### Complexity Rationale
This is rated Nuanced because SHA-1 hashing superficially appears secure, but hashing predictable inputs does not produce unpredictable outputs.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to analyze the entropy of the hash input to detect insufficient randomness.
