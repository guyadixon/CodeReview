# Security Companion Document: main.cpp

## Vulnerability: XOR-Based Fake DES Encryption

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L80-L101  

### Description
The `des_xor_encrypt` function claims to perform DES encryption but actually implements a simple repeating-key XOR cipher. XOR with a short repeating key provides no real cryptographic security — it is trivially broken with frequency analysis or known-plaintext attacks.

### Exploitation Scenario
An attacker who intercepts encrypted records recognizes the XOR pattern (the key repeats every 8 bytes). Using a known-plaintext attack, they recover the key and decrypt all records.

### Remediation Guidance
Use OpenSSL for proper AES encryption:
```cpp
#include <openssl/evp.h>
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
```

### Complexity Rationale
This is rated Moderate because the function is named `des_xor_encrypt` and uses a DES key constant, creating the appearance of DES encryption. A reviewer must read the implementation to realize it is just XOR.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools would need to analyze the function body to recognize that XOR does not constitute real encryption.

---

## Vulnerability: Hardcoded Encryption Key

**CWE:** CWE-327  
**OWASP:** A02  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L18-L18  

### Description
The encryption key is hardcoded as `{'s','3','c','r','3','t','!','!'}` in a static constant. Anyone with access to the source code or binary can extract the key.

### Exploitation Scenario
An attacker uses `strings` on the compiled binary to extract the key value and decrypts all stored records.

### Remediation Guidance
Load encryption keys from environment variables:
```cpp
const char *key = std::getenv("ENCRYPTION_KEY");
```

### Complexity Rationale
This is rated Obvious because the key is a plaintext character array assigned to a named constant.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify hardcoded byte arrays used in encryption contexts.

---

## Vulnerability: std::hash Used as Cryptographic Hash Replacement

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L54-L78  

### Description
The `md5_hash` and `sha1_hash` functions use `std::hash<std::string>` (a non-cryptographic hash designed for hash tables) as a replacement for MD5 and SHA-1. `std::hash` provides no collision resistance, no preimage resistance, and is trivially reversible for short inputs. These functions are used for password hashing and integrity signatures.

### Exploitation Scenario
An attacker analyzes the hash function and discovers it uses `std::hash`, which has extremely high collision rates for security purposes. They craft inputs producing the same hash as a target password, bypassing authentication.

### Remediation Guidance
Use OpenSSL for proper cryptographic hashing:
```cpp
#include <openssl/evp.h>
unsigned char hash[EVP_MAX_MD_SIZE];
unsigned int hash_len;
EVP_Digest(input.c_str(), input.size(), hash, &hash_len, EVP_sha256(), NULL);
```

### Complexity Rationale
This is rated Nuanced because the functions are named `md5_hash` and `sha1_hash`, suggesting standard algorithms. A reviewer must recognize that `std::hash` is not a cryptographic hash function.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to understand that `std::hash` is not suitable for cryptographic purposes and trace its usage to authentication and integrity contexts.

---

## Vulnerability: Weak Hash Used for Data Integrity Signatures

**CWE:** CWE-328  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L149-L151  

### Description
The `compute_signature` function uses the `md5_hash` function (which internally uses `std::hash`) to create integrity signatures. This provides no real integrity protection — collisions are trivial to find.

### Exploitation Scenario
An attacker crafts different data that produces the same hash output, replacing record content while the integrity check still passes.

### Remediation Guidance
Use HMAC with SHA-256 via OpenSSL:
```cpp
#include <openssl/hmac.h>
HMAC(EVP_sha256(), key, key_len, data, data_len, result, &result_len);
```

### Complexity Rationale
This is rated Moderate because the function name suggests HMAC-like behavior but uses a non-cryptographic hash.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the signature function to its underlying non-cryptographic hash implementation.

---

## Vulnerability: Predictable Session Token Generation via rand()

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Moderate  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L153-L162  

### Description
Session tokens are generated using `rand()` seeded with `time(nullptr)` via `srand()`. The C `rand()` function is not cryptographically secure and produces predictable output. The seed is the current Unix timestamp, which an attacker can easily determine.

### Exploitation Scenario
An attacker who knows the approximate server startup time seeds their own `rand()` with the same timestamp, calls `rand()` the same number of times, and reproduces valid session tokens.

### Remediation Guidance
Use `/dev/urandom` or `std::random_device` for cryptographically secure random bytes:
```cpp
#include <random>
std::random_device rd;
std::uniform_int_distribution<int> dist(0, 15);
```

### Complexity Rationale
This is rated Moderate because `rand()` is commonly known to be weak, but connecting `srand(time(nullptr))` to predictable session tokens requires understanding the PRNG lifecycle.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `rand()` usage in security-sensitive contexts.

---

## Vulnerability: Predictable API Token Generation

**CWE:** CWE-330  
**OWASP:** A02  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L164-L169  

### Description
API tokens are generated by hashing a predictable string `"tkn-{seq}-{timestamp}"` with the custom SHA-1 function and truncating to 24 characters. Both the sequential counter and timestamp are predictable, making tokens reproducible.

### Exploitation Scenario
An attacker who knows the approximate generation time and can estimate the sequence number computes the same hash, reproducing valid API tokens.

### Remediation Guidance
Use `std::random_device` for token generation:
```cpp
std::random_device rd;
std::ostringstream oss;
for (int i = 0; i < 24; i++) oss << std::hex << (rd() % 16);
```

### Complexity Rationale
This is rated Nuanced because the function uses hashing which superficially appears secure, but the predictable inputs make the output reproducible.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools would need to analyze the entropy of the hash input to detect insufficient randomness.
