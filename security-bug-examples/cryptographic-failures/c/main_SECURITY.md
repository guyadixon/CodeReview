# Security Companion Document: main.c

## Vulnerability: XOR-Based Fake DES Encryption

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L91-L97  

### Description
The `des_ecb_xor` function claims to perform DES encryption but actually implements a simple repeating-key XOR cipher. XOR with a short repeating key provides no real cryptographic security — it is trivially broken with frequency analysis or known-plaintext attacks.

### Exploitation Scenario
An attacker who intercepts encrypted records recognizes the XOR pattern (the key repeats every 8 bytes). Using known-plaintext attack (e.g., knowing the JSON structure of stored data), they recover the key and decrypt all records.

### Remediation Guidance
Use a proper AES implementation via OpenSSL:
```c
#include <openssl/evp.h>
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
```

### Complexity Rationale
This is rated Moderate because the function is named `des_ecb_xor` and uses a DES key, creating the appearance of DES encryption. A reviewer must read the implementation to realize it is just XOR.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools would need to analyze the function body to recognize that the XOR operation does not constitute real encryption. Tools that check for known crypto library calls may flag the absence of proper crypto APIs.

---

## Vulnerability: Hardcoded Encryption Key

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L15-L15  

### Description
The encryption key is hardcoded as `{'s','3','c','r','3','t','!','!'}` in a static constant. Anyone with access to the source code or binary can extract the key.

### Exploitation Scenario
An attacker uses `strings` on the compiled binary to extract the key value and decrypts all stored records.

### Remediation Guidance
Load encryption keys from environment variables:
```c
const char *key = getenv("ENCRYPTION_KEY");
```

### Complexity Rationale
This is rated Obvious because the key is a plaintext character array assigned to a named constant.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded byte arrays used in encryption contexts.

---

## Vulnerability: Custom Non-Cryptographic Hash Functions Replacing MD5/SHA-1

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L54-L89  

### Description
The `md5_simple` and `sha1_simple` functions are custom hash implementations that do not implement actual MD5 or SHA-1 algorithms. They use simple multiplicative hashing that produces weak, easily colliding outputs. These are used for password hashing and integrity signatures, providing no real security.

### Exploitation Scenario
An attacker analyzes the custom hash function and discovers it has extremely high collision rates. They craft inputs that produce the same hash as a target password, bypassing authentication. The weak hash also makes brute-force trivial.

### Remediation Guidance
Use OpenSSL for proper cryptographic hashing, and use bcrypt/argon2 for passwords:
```c
#include <openssl/evp.h>
unsigned char hash[EVP_MAX_MD_SIZE];
unsigned int hash_len;
EVP_Digest(input, strlen(input), hash, &hash_len, EVP_sha256(), NULL);
```

### Complexity Rationale
This is rated Nuanced because the functions are named `md5_simple` and `sha1_simple`, suggesting they implement standard algorithms. A reviewer must carefully read the implementation to realize these are not real MD5/SHA-1 but weak custom hashes.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to analyze the function body to determine that the implementation does not match the MD5/SHA-1 specification. Most tools check for known API calls rather than analyzing custom implementations.

---

## Vulnerability: MD5-Like Hash Used for Data Integrity Signatures

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L176-L180  

### Description
The `compute_signature` function uses the custom `md5_simple` hash to create integrity signatures by concatenating data with a secret. Even if this were real MD5, the approach would be vulnerable to collision and length extension attacks. With the weak custom hash, collisions are trivial.

### Exploitation Scenario
An attacker crafts different data that produces the same hash output, replacing record content while the integrity check still passes.

### Remediation Guidance
Use HMAC with SHA-256 via OpenSSL:
```c
#include <openssl/hmac.h>
HMAC(EVP_sha256(), key, key_len, data, data_len, result, &result_len);
```

### Complexity Rationale
This is rated Moderate because the function name suggests HMAC-like behavior but uses a weak custom hash with simple concatenation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that custom hash functions used for integrity are insecure.

---

## Vulnerability: Predictable Session Token Generation via rand()

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L204-L215  

### Description
Session tokens are generated using `rand()` seeded with `time(NULL)` via `srand()`. The C `rand()` function is not cryptographically secure and produces predictable output. The seed is the current Unix timestamp, which an attacker can easily determine.

### Exploitation Scenario
An attacker who knows the approximate server startup time seeds their own `rand()` with the same timestamp, calls `rand()` the same number of times, and reproduces valid session tokens.

### Remediation Guidance
Use `/dev/urandom` for cryptographically secure random bytes:
```c
int fd = open("/dev/urandom", O_RDONLY);
unsigned char buf[32];
read(fd, buf, sizeof(buf));
close(fd);
```

### Complexity Rationale
This is rated Moderate because `rand()` is commonly known to be weak, but the connection between `srand(time(NULL))` at startup and predictable session tokens requires understanding the PRNG lifecycle.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `rand()` usage in security-sensitive contexts.

---

## Vulnerability: Predictable API Token Generation

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L258-L268  

### Description
API tokens are generated by hashing a predictable string `"tkn-{seq}-{timestamp}"` with the custom SHA-1 function and truncating to 24 characters. Both the sequential counter and timestamp are predictable, making tokens reproducible.

### Exploitation Scenario
An attacker who knows the approximate generation time and can estimate the sequence number computes the same hash, reproducing valid API tokens.

### Remediation Guidance
Use `/dev/urandom` for token generation:
```c
unsigned char buf[12];
int fd = open("/dev/urandom", O_RDONLY);
read(fd, buf, sizeof(buf));
close(fd);
```

### Complexity Rationale
This is rated Nuanced because the function uses hashing which superficially appears secure, but the predictable inputs make the output reproducible.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to analyze the entropy of the hash input to detect insufficient randomness.
