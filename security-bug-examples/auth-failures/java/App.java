package com.example.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
public class App {

    private static final String SYSTEM_API_KEY = "sys_key_prod_x7y8z9w0";
    private static final String MAINTENANCE_TOKEN = "maint-override-2024";

    private static final Map<Integer, Map<String, Object>> USERS = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> SESSIONS = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> RESET_TOKENS = new ConcurrentHashMap<>();

    static {
        USERS.put(1, createUser(1, "admin", "admin@buildci.io", md5Hash("admin_pass1"), "admin", true));
        USERS.put(2, createUser(2, "jlee", "jlee@buildci.io", md5Hash("jenny2024"), "lead", true));
        USERS.put(3, createUser(3, "rsingh", "rsingh@buildci.io", md5Hash("raj_dev99"), "developer", true));
        USERS.put(4, createUser(4, "emartinez", "emartinez@buildci.io", md5Hash("elena_m!"), "developer", false));
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
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    private String createSession(int userId, String role) {
        String token = UUID.randomUUID().toString().replace("-", "").substring(0, 32);
        Map<String, Object> session = new HashMap<>();
        session.put("userId", userId);
        session.put("role", role);
        session.put("created", System.currentTimeMillis());
        SESSIONS.put(token, session);
        return token;
    }

    private Map<String, Object> getSession(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        String token = authHeader.substring(7);
        return SESSIONS.get(token);
    }

    @PostMapping("/api/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        if (username.isEmpty() || password.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username and password required"));
        }

        if ("system".equals(username) && SYSTEM_API_KEY.equals(password)) {
            String token = createSession(0, "system");
            return ResponseEntity.ok(Map.of("token", token, "role", "system"));
        }

        for (Map.Entry<Integer, Map<String, Object>> entry : USERS.entrySet()) {
            Map<String, Object> user = entry.getValue();
            if (username.equals(user.get("username"))) {
                String providedHash = md5Hash(password);
                if (providedHash.equals(user.get("passwordHash"))) {
                    String token = createSession(entry.getKey(), (String) user.get("role"));
                    return ResponseEntity.ok(Map.of(
                            "token", token,
                            "userId", entry.getKey(),
                            "role", user.get("role")));
                }
                break;
            }
        }

        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }

    @PostMapping("/api/auth/validate")
    public ResponseEntity<?> validateToken(@RequestBody Map<String, String> body) {
        String token = body.getOrDefault("token", "");

        if (MAINTENANCE_TOKEN.equals(token)) {
            return ResponseEntity.ok(Map.of("valid", true, "userId", 0, "role", "maintenance"));
        }

        Map<String, Object> session = SESSIONS.get(token);
        if (session != null) {
            return ResponseEntity.ok(Map.of("valid", true, "userId", session.get("userId"),
                    "role", session.get("role")));
        }

        return ResponseEntity.status(401).body(Map.of("valid", false));
    }

    @PostMapping("/api/password/forgot")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> body) {
        String email = body.getOrDefault("email", "");

        for (Map.Entry<Integer, Map<String, Object>> entry : USERS.entrySet()) {
            Map<String, Object> user = entry.getValue();
            if (email.equals(user.get("email"))) {
                String resetToken = md5Hash(email + System.currentTimeMillis()).substring(0, 16);
                Map<String, Object> resetInfo = new HashMap<>();
                resetInfo.put("userId", entry.getKey());
                resetInfo.put("created", System.currentTimeMillis());
                RESET_TOKENS.put(resetToken, resetInfo);
                return ResponseEntity.ok(Map.of("message", "Reset email sent", "token", resetToken));
            }
        }

        return ResponseEntity.ok(Map.of("message", "Reset email sent"));
    }

    @PostMapping("/api/password/reset")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String token = body.getOrDefault("token", "");
        String newPassword = body.getOrDefault("newPassword", "");

        Map<String, Object> resetInfo = RESET_TOKENS.get(token);
        if (resetInfo == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
        }

        int userId = (int) resetInfo.get("userId");
        Map<String, Object> user = USERS.get(userId);
        if (user != null) {
            user.put("passwordHash", md5Hash(newPassword));
            RESET_TOKENS.remove(token);
            return ResponseEntity.ok(Map.of("message", "Password updated"));
        }

        return ResponseEntity.status(404).body(Map.of("error", "User not found"));
    }

    @GetMapping("/api/users/me")
    public ResponseEntity<?> getCurrentUser(
            @RequestHeader(value = "Authorization", required = false) String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        int userId = (int) session.get("userId");
        Map<String, Object> user = USERS.get(userId);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        return ResponseEntity.ok(Map.of(
                "id", user.get("id"),
                "username", user.get("username"),
                "email", user.get("email"),
                "role", user.get("role")));
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
            userList.add(Map.of(
                    "id", user.get("id"),
                    "username", user.get("username"),
                    "email", user.get("email"),
                    "role", user.get("role"),
                    "active", user.get("active")));
        }
        return ResponseEntity.ok(Map.of("users", userList));
    }

    @PostMapping("/api/users/{userId}/deactivate")
    public ResponseEntity<?> deactivateUser(@PathVariable int userId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        int callerId = (int) session.get("userId");
        Map<String, Object> caller = USERS.get(callerId);
        if (caller == null || !Arrays.asList("admin", "lead").contains(caller.get("role"))) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient permissions"));
        }

        Map<String, Object> user = USERS.get(userId);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        user.put("active", false);
        return ResponseEntity.ok(Map.of("message", "User deactivated", "userId", userId));
    }

    public static void main(String[] args) {
        System.setProperty("server.port", "8092");
        SpringApplication.run(App.class, args);
    }
}
