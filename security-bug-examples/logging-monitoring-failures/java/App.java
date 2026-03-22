package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
public class App {

    private static final String API_SECRET = "sk-prod-logging-8a7b6c5d4e3f";

    private static final Map<Integer, Map<String, Object>> users = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> sessions = new ConcurrentHashMap<>();
    private static final List<Map<String, Object>> transactions =
            Collections.synchronizedList(new ArrayList<>());

    static {
        users.put(1, createUser(1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!",
                "admin", true, true, "ak-admin-x7k9m2"));
        users.put(2, createUser(2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024",
                "manager", true, false, "ak-jdoe-p3q8r1"));
        users.put(3, createUser(3, "asmith", "asmith@acmecorp.io", "alice_pass",
                "developer", true, false, "ak-asmith-w5t6y4"));
        users.put(4, createUser(4, "bwilson", "bwilson@acmecorp.io", "B0b_W1ls0n",
                "analyst", false, false, "ak-bwilson-z2v8n3"));
    }

    private static Map<String, Object> createUser(int id, String username, String email,
                                                    String password, String role, boolean active,
                                                    boolean mfaEnabled, String apiKey) {
        Map<String, Object> user = new HashMap<>();
        user.put("id", id);
        user.put("username", username);
        user.put("email", email);
        user.put("password", password);
        user.put("role", role);
        user.put("active", active);
        user.put("mfa_enabled", mfaEnabled);
        user.put("api_key", apiKey);
        return user;
    }

    private String createSession(int userId) {
        try {
            String raw = userId + "-" + System.currentTimeMillis();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(raw.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            String token = sb.toString();
            Map<String, Object> session = new HashMap<>();
            session.put("user_id", userId);
            session.put("created", System.currentTimeMillis());
            sessions.put(token, session);
            return token;
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, Object> getSession(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return sessions.get(authHeader.substring(7));
        }
        return null;
    }

    @PostMapping("/api/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        for (Map.Entry<Integer, Map<String, Object>> entry : users.entrySet()) {
            Map<String, Object> user = entry.getValue();
            if (user.get("username").equals(username)) {
                if (!(boolean) user.get("active")) {
                    return ResponseEntity.status(403).body(Map.of("error", "Account disabled"));
                }

                if (user.get("password").equals(password)) {
                    String token = createSession(entry.getKey());
                    return ResponseEntity.ok(Map.of(
                            "token", token,
                            "user_id", entry.getKey(),
                            "role", user.get("role"),
                            "password", user.get("password"),
                            "api_key", user.get("api_key")
                    ));
                }

                return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
            }
        }

        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }

    @GetMapping("/api/admin/users")
    public ResponseEntity<?> listUsers(
            @RequestHeader(value = "Authorization", defaultValue = "") String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, Object> user : users.values()) {
            result.add(Map.of(
                    "id", user.get("id"),
                    "username", user.get("username"),
                    "email", user.get("email"),
                    "role", user.get("role"),
                    "active", user.get("active")
            ));
        }
        return ResponseEntity.ok(Map.of("users", result));
    }

    @PutMapping("/api/admin/users/{userId}/role")
    public ResponseEntity<?> changeUserRole(
            @RequestHeader(value = "Authorization", defaultValue = "") String auth,
            @PathVariable int userId,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> target = users.get(userId);
        if (target == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Target user not found"));
        }

        String oldRole = (String) target.get("role");
        String newRole = body.getOrDefault("role", "");
        target.put("role", newRole);

        return ResponseEntity.ok(Map.of(
                "message", "Role updated",
                "user_id", userId,
                "old_role", oldRole,
                "new_role", newRole
        ));
    }

    @PostMapping("/api/admin/users/{userId}/deactivate")
    public ResponseEntity<?> deactivateUser(
            @RequestHeader(value = "Authorization", defaultValue = "") String auth,
            @PathVariable int userId) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> caller = users.get(session.get("user_id"));
        if (caller == null || !"admin".equals(caller.get("role"))) {
            return ResponseEntity.status(403).body(Map.of("error", "Admin access required"));
        }

        Map<String, Object> target = users.get(userId);
        if (target == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Target user not found"));
        }

        target.put("active", false);
        return ResponseEntity.ok(Map.of("message", "User deactivated", "user_id", userId));
    }

    @PostMapping("/api/transactions")
    public ResponseEntity<?> createTransaction(
            @RequestHeader(value = "Authorization", defaultValue = "") String auth,
            @RequestBody Map<String, Object> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Object amountObj = body.getOrDefault("amount", 0);
        String recipient = (String) body.getOrDefault("recipient", "");
        String description = (String) body.getOrDefault("description", "");

        if (recipient.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Recipient required"));
        }

        Map<String, Object> transaction = new HashMap<>();
        transaction.put("id", transactions.size() + 1);
        transaction.put("user_id", session.get("user_id"));
        transaction.put("amount", amountObj);
        transaction.put("recipient", recipient);
        transaction.put("description", description);
        transaction.put("timestamp", System.currentTimeMillis());
        transaction.put("status", "completed");
        transactions.add(transaction);

        return ResponseEntity.status(201).body(Map.of(
                "message", "Transaction completed", "transaction", transaction));
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/api/transactions/bulk")
    public ResponseEntity<?> bulkTransfer(
            @RequestHeader(value = "Authorization", defaultValue = "") String auth,
            @RequestBody Map<String, Object> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        List<Map<String, Object>> transfers =
                (List<Map<String, Object>>) body.getOrDefault("transfers", List.of());

        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> t : transfers) {
            Map<String, Object> transaction = new HashMap<>();
            transaction.put("id", transactions.size() + 1);
            transaction.put("user_id", session.get("user_id"));
            transaction.put("amount", t.getOrDefault("amount", 0));
            transaction.put("recipient", t.getOrDefault("recipient", ""));
            transaction.put("description", t.getOrDefault("description", ""));
            transaction.put("timestamp", System.currentTimeMillis());
            transaction.put("status", "completed");
            transactions.add(transaction);
            results.add(transaction);
        }

        return ResponseEntity.status(201).body(Map.of(
                "message", results.size() + " transfers completed",
                "transactions", results));
    }

    @PostMapping("/api/export/data")
    public ResponseEntity<?> exportData(
            @RequestHeader(value = "Authorization", defaultValue = "") String auth,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String exportType = body.getOrDefault("type", "");

        if ("users".equals(exportType)) {
            List<Map<String, Object>> exportData = new ArrayList<>();
            for (Map<String, Object> u : users.values()) {
                exportData.add(Map.of(
                        "id", u.get("id"),
                        "username", u.get("username"),
                        "email", u.get("email"),
                        "password", u.get("password"),
                        "api_key", u.get("api_key"),
                        "role", u.get("role")
                ));
            }
            return ResponseEntity.ok(Map.of("export", exportData));
        }

        if ("transactions".equals(exportType)) {
            return ResponseEntity.ok(Map.of("export", transactions));
        }

        return ResponseEntity.badRequest().body(Map.of("error", "Unknown export type"));
    }

    @PostMapping("/api/settings/api-key")
    public ResponseEntity<?> regenerateApiKey(
            @RequestHeader(value = "Authorization", defaultValue = "") String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> user = users.get(session.get("user_id"));
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        String oldKey = (String) user.get("api_key");
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest((user.get("username") + "" + System.currentTimeMillis()).getBytes());
            StringBuilder sb = new StringBuilder("ak-");
            for (int i = 0; i < 6; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            String newKey = sb.toString();
            user.put("api_key", newKey);
            return ResponseEntity.ok(Map.of(
                    "message", "API key regenerated",
                    "old_key", oldKey,
                    "new_key", newKey));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/api/settings/mfa")
    public ResponseEntity<?> toggleMfa(
            @RequestHeader(value = "Authorization", defaultValue = "") String auth,
            @RequestBody Map<String, Object> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> user = users.get(session.get("user_id"));
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        boolean enabled = (boolean) body.getOrDefault("enabled", false);
        user.put("mfa_enabled", enabled);

        return ResponseEntity.ok(Map.of("message", "MFA setting updated", "mfa_enabled", enabled));
    }

    @PostMapping("/api/validate-key")
    public ResponseEntity<?> validateApiKey(@RequestBody Map<String, String> body) {
        String key = body.getOrDefault("api_key", "");

        for (Map.Entry<Integer, Map<String, Object>> entry : users.entrySet()) {
            Map<String, Object> user = entry.getValue();
            if (key.equals(user.get("api_key"))) {
                return ResponseEntity.ok(Map.of(
                        "valid", true,
                        "user_id", entry.getKey(),
                        "username", user.get("username"),
                        "role", user.get("role")
                ));
            }
        }

        return ResponseEntity.status(401).body(Map.of("valid", false));
    }

    @GetMapping("/api/health")
    public ResponseEntity<?> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "healthy", "service", "logging-api"));
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
