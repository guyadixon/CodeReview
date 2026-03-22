package com.example.cryptoservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@SpringBootApplication
@RestController
public class App {

    private static final byte[] DES_KEY = "s3cr3t!!".getBytes();
    private static final String SIGNING_SECRET = "platform-sign-key-2024";

    private static final Map<Integer, Map<String, Object>> USERS = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> SESSIONS = new ConcurrentHashMap<>();
    private static final Map<Integer, Map<String, Object>> RECORDS = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> API_TOKENS = new ConcurrentHashMap<>();

    private static final AtomicInteger recordCounter = new AtomicInteger(0);
    private static final AtomicInteger tokenSeq = new AtomicInteger(3000);
    private static final Random rng = new Random(System.currentTimeMillis() / 1000);

    static {
        USERS.put(1, createUser(1, "admin", "admin@securevault.io", md5Hash("admin2024!"), "admin", true));
        USERS.put(2, createUser(2, "klee", "klee@securevault.io", md5Hash("kevin_l99"), "manager", true));
        USERS.put(3, createUser(3, "apatel", "apatel@securevault.io", sha1Hash("anita_p!"), "analyst", true));
        USERS.put(4, createUser(4, "bwong", "bwong@securevault.io", md5Hash("brian_view"), "viewer", false));
    }

    private static Map<String, Object> createUser(int id, String username, String email,
                                                    String passwordHash, String role, boolean active) {
        Map<String, Object> user = new HashMap<>();
        user.put("id", id);
        user.put("username", username);
        user.put("email", email);
        user.put("passwordHash", passwordHash);
        user.put("role", role);
        user.put("active", active);
        return user;
    }

    private static String md5Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return ""; }
    }

    private static String sha1Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return ""; }
    }

    private String createSession(int userId) {
        String token = "";
        synchronized (rng) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 32; i++) {
                sb.append(Integer.toHexString(rng.nextInt(16)));
            }
            token = sb.toString();
        }
        Map<String, Object> session = new HashMap<>();
        session.put("userId", userId);
        session.put("created", System.currentTimeMillis());
        SESSIONS.put(token, session);
        return token;
    }

    private Map<String, Object> getSession(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return null;
        return SESSIONS.get(authHeader.substring(7));
    }

    private String desEncrypt(String plaintext) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(DES_KEY, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) { return ""; }
    }

    private String desDecrypt(String ciphertext) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(DES_KEY, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decrypted);
        } catch (Exception e) { return ""; }
    }

    private String computeSignature(String data) {
        return md5Hash(data + SIGNING_SECRET);
    }

    private String generateApiToken() {
        int seq = tokenSeq.incrementAndGet();
        long ts = System.currentTimeMillis() / 1000;
        return sha1Hash("tkn-" + seq + "-" + ts).substring(0, 24);
    }

    @PostMapping("/api/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        if (username.isEmpty() || password.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username and password required"));
        }

        for (Map.Entry<Integer, Map<String, Object>> entry : USERS.entrySet()) {
            Map<String, Object> user = entry.getValue();
            if (username.equals(user.get("username"))) {
                String providedHash;
                if (entry.getKey() == 3) {
                    providedHash = sha1Hash(password);
                } else {
                    providedHash = md5Hash(password);
                }
                if (providedHash.equals(user.get("passwordHash"))) {
                    String token = createSession(entry.getKey());
                    return ResponseEntity.ok(Map.of("token", token, "userId", entry.getKey(),
                            "role", user.get("role")));
                }
                break;
            }
        }

        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }

    @PostMapping("/api/records")
    public ResponseEntity<?> createRecord(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String content = body.getOrDefault("content", "");
        if (content.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Content required"));
        }

        int recordId = recordCounter.incrementAndGet();
        String encrypted = desEncrypt(content);
        String signature = computeSignature(content);

        Map<String, Object> record = new HashMap<>();
        record.put("id", recordId);
        record.put("encryptedContent", encrypted);
        record.put("signature", signature);
        record.put("ownerId", session.get("userId"));
        record.put("created", System.currentTimeMillis());
        RECORDS.put(recordId, record);

        return ResponseEntity.ok(Map.of("id", recordId, "signature", signature,
                "message", "Record encrypted and stored"));
    }

    @GetMapping("/api/records/{recordId}")
    public ResponseEntity<?> getRecord(@PathVariable int recordId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> record = RECORDS.get(recordId);
        if (record == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Record not found"));
        }

        String decrypted = desDecrypt((String) record.get("encryptedContent"));
        return ResponseEntity.ok(Map.of("id", record.get("id"), "content", decrypted,
                "signature", record.get("signature"), "ownerId", record.get("ownerId")));
    }

    @PostMapping("/api/records/{recordId}/verify")
    public ResponseEntity<?> verifyRecord(@PathVariable int recordId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> record = RECORDS.get(recordId);
        if (record == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Record not found"));
        }

        String decrypted = desDecrypt((String) record.get("encryptedContent"));
        String expectedSig = computeSignature(decrypted);
        boolean valid = expectedSig.equals(record.get("signature"));

        return ResponseEntity.ok(Map.of("id", recordId, "integrityValid", valid));
    }

    @PostMapping("/api/tokens/generate")
    public ResponseEntity<?> generateToken(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @RequestBody(required = false) Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String label = (body != null) ? body.getOrDefault("label", "default") : "default";
        String apiToken = generateApiToken();

        Map<String, Object> tokenInfo = new HashMap<>();
        tokenInfo.put("label", label);
        tokenInfo.put("ownerId", session.get("userId"));
        tokenInfo.put("created", System.currentTimeMillis());
        API_TOKENS.put(apiToken, tokenInfo);

        return ResponseEntity.ok(Map.of("token", apiToken, "label", label));
    }

    @PostMapping("/api/tokens/validate")
    public ResponseEntity<?> validateToken(@RequestBody Map<String, String> body) {
        String token = body.getOrDefault("token", "");
        Map<String, Object> tokenInfo = API_TOKENS.get(token);
        if (tokenInfo != null) {
            return ResponseEntity.ok(Map.of("valid", true, "label", tokenInfo.get("label"),
                    "ownerId", tokenInfo.get("ownerId")));
        }
        return ResponseEntity.status(401).body(Map.of("valid", false));
    }

    @PostMapping("/api/hash")
    public ResponseEntity<?> hashData(@RequestBody Map<String, String> body) {
        String value = body.getOrDefault("value", "");
        if (value.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Value required"));
        }

        String algorithm = body.getOrDefault("algorithm", "md5");
        String result;
        if ("sha1".equals(algorithm)) {
            result = sha1Hash(value);
        } else {
            result = md5Hash(value);
        }

        return ResponseEntity.ok(Map.of("hash", result, "algorithm", algorithm));
    }

    @PostMapping("/api/encrypt")
    public ResponseEntity<?> encryptData(@RequestBody Map<String, String> body) {
        String plaintext = body.getOrDefault("plaintext", "");
        if (plaintext.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Plaintext required"));
        }
        return ResponseEntity.ok(Map.of("ciphertext", desEncrypt(plaintext)));
    }

    @PostMapping("/api/decrypt")
    public ResponseEntity<?> decryptData(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String ciphertext = body.getOrDefault("ciphertext", "");
        if (ciphertext.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Ciphertext required"));
        }

        String decrypted = desDecrypt(ciphertext);
        if (decrypted.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Decryption failed"));
        }
        return ResponseEntity.ok(Map.of("plaintext", decrypted));
    }

    @GetMapping("/api/users")
    public ResponseEntity<?> listUsers(
            @RequestHeader(value = "Authorization", required = false) String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        List<Map<String, Object>> userList = new ArrayList<>();
        for (Map<String, Object> user : USERS.values()) {
            userList.add(Map.of("id", user.get("id"), "username", user.get("username"),
                    "email", user.get("email"), "role", user.get("role"),
                    "active", user.get("active")));
        }
        return ResponseEntity.ok(Map.of("users", userList));
    }

    @PutMapping("/api/users/me/password")
    public ResponseEntity<?> changePassword(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String newPassword = body.getOrDefault("newPassword", "");
        if (newPassword.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "New password required"));
        }

        int userId = (int) session.get("userId");
        Map<String, Object> user = USERS.get(userId);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        user.put("passwordHash", md5Hash(newPassword));
        return ResponseEntity.ok(Map.of("message", "Password updated"));
    }

    public static void main(String[] args) {
        System.setProperty("server.port", "8097");
        SpringApplication.run(App.class, args);
    }
}
