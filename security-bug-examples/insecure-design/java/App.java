package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
public class App {

    private static final String DB_URL = "jdbc:h2:mem:designdb";
    private static final String DB_USER = "sa";
    private static final String DB_PASS = "admin123";
    private static final String SMTP_HOST = "smtp.internal.acmecorp.io";
    private static final String SMTP_CREDENTIAL = "SmtpRelay#Prod2024!";

    private static final Map<Integer, Map<String, Object>> users = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> sessions = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> resetTokens = new ConcurrentHashMap<>();

    static {
        users.put(1, createUser(1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", true));
        users.put(2, createUser(2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", true));
        users.put(3, createUser(3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", true));
        users.put(4, createUser(4, "bwilson", "bwilson@acmecorp.io", "B0b_W1ls0n", "analyst", false));
    }

    private static Map<String, Object> createUser(int id, String username, String email,
                                                    String password, String role, boolean active) {
        Map<String, Object> user = new HashMap<>();
        user.put("id", id);
        user.put("username", username);
        user.put("email", email);
        user.put("password", password);
        user.put("role", role);
        user.put("active", active);
        user.put("failed_attempts", 0);
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
                    return ResponseEntity.status(403).body(Map.of(
                        "error", "Account '" + username + "' is deactivated. Contact admin@acmecorp.io."
                    ));
                }

                if (user.get("password").equals(password)) {
                    user.put("failed_attempts", 0);
                    String token = createSession(entry.getKey());
                    return ResponseEntity.ok(Map.of(
                        "token", token, "user_id", entry.getKey(), "role", user.get("role")
                    ));
                }

                int attempts = (int) user.get("failed_attempts") + 1;
                user.put("failed_attempts", attempts);
                return ResponseEntity.status(401).body(Map.of(
                    "error", "Incorrect password", "attempts", attempts
                ));
            }
        }

        return ResponseEntity.status(404).body(Map.of(
            "error", "No account found for username '" + username + "'"
        ));
    }

    @PostMapping("/api/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String email = body.getOrDefault("email", "");
        String password = body.getOrDefault("password", "");

        if (username.isEmpty() || email.isEmpty() || password.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "All fields required"));
        }

        for (Map<String, Object> user : users.values()) {
            if (user.get("username").equals(username)) {
                return ResponseEntity.status(409).body(Map.of(
                    "error", "Username '" + username + "' is already taken"
                ));
            }
            if (user.get("email").equals(email)) {
                return ResponseEntity.status(409).body(Map.of(
                    "error", "Email '" + email + "' is already registered"
                ));
            }
        }

        int newId = users.keySet().stream().max(Integer::compareTo).orElse(0) + 1;
        users.put(newId, createUser(newId, username, email, password, "viewer", true));
        return ResponseEntity.status(201).body(Map.of("message", "User registered", "user_id", newId));
    }

    @PostMapping("/api/password-reset")
    public ResponseEntity<?> requestPasswordReset(@RequestBody Map<String, String> body) {
        String email = body.getOrDefault("email", "");

        for (Map.Entry<Integer, Map<String, Object>> entry : users.entrySet()) {
            Map<String, Object> user = entry.getValue();
            if (user.get("email").equals(email)) {
                try {
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    byte[] hash = md.digest((email + System.currentTimeMillis()).getBytes());
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 8; i++) {
                        sb.append(String.format("%02x", hash[i]));
                    }
                    String resetToken = sb.toString();
                    Map<String, Object> tokenInfo = new HashMap<>();
                    tokenInfo.put("user_id", entry.getKey());
                    tokenInfo.put("created", System.currentTimeMillis());
                    resetTokens.put(resetToken, tokenInfo);

                    return ResponseEntity.ok(Map.of(
                        "message", "Password reset link sent",
                        "token", resetToken,
                        "smtp_server", SMTP_HOST
                    ));
                } catch (Exception e) {
                    return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
                }
            }
        }

        return ResponseEntity.status(404).body(Map.of(
            "error", "No account associated with '" + email + "'"
        ));
    }

    @PostMapping("/api/password-reset/confirm")
    public ResponseEntity<?> confirmPasswordReset(@RequestBody Map<String, String> body) {
        String token = body.getOrDefault("token", "");
        String newPassword = body.getOrDefault("new_password", "");

        Map<String, Object> resetInfo = resetTokens.get(token);
        if (resetInfo == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
        }

        Map<String, Object> user = users.get(resetInfo.get("user_id"));
        if (user != null) {
            user.put("password", newPassword);
            resetTokens.remove(token);
            return ResponseEntity.ok(Map.of("message", "Password updated successfully"));
        }

        return ResponseEntity.status(404).body(Map.of("error", "User not found"));
    }

    @GetMapping("/api/users/me")
    public ResponseEntity<?> getCurrentUser(@RequestHeader(value = "Authorization", defaultValue = "") String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> user = users.get(session.get("user_id"));
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        return ResponseEntity.ok(Map.of(
            "id", user.get("id"), "username", user.get("username"),
            "email", user.get("email"), "role", user.get("role")
        ));
    }

    @PutMapping("/api/users/me/password")
    public ResponseEntity<?> changePassword(@RequestHeader(value = "Authorization", defaultValue = "") String auth,
                                             @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String newPassword = body.getOrDefault("new_password", "");
        if (newPassword.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "New password required"));
        }

        Map<String, Object> user = users.get(session.get("user_id"));
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        user.put("password", newPassword);
        return ResponseEntity.ok(Map.of("message", "Password updated"));
    }

    @PostMapping("/api/reports/generate")
    public ResponseEntity<?> generateReport(@RequestHeader(value = "Authorization", defaultValue = "") String auth,
                                             @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String reportType = body.getOrDefault("type", "");

        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            Statement stmt = conn.createStatement();
            ResultSet rs;

            if ("users".equals(reportType)) {
                rs = stmt.executeQuery("SELECT * FROM users");
            } else if ("audit".equals(reportType)) {
                rs = stmt.executeQuery("SELECT * FROM audit_log");
            } else {
                rs = stmt.executeQuery("SELECT * FROM " + reportType);
            }

            List<Map<String, Object>> rows = new ArrayList<>();
            int colCount = rs.getMetaData().getColumnCount();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                for (int i = 1; i <= colCount; i++) {
                    row.put(rs.getMetaData().getColumnName(i), rs.getObject(i));
                }
                rows.add(row);
            }
            conn.close();
            return ResponseEntity.ok(Map.of("report", rows));

        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return ResponseEntity.status(500).body(Map.of(
                "error", "Report generation failed",
                "details", e.getMessage(),
                "trace", sw.toString(),
                "database_url", DB_URL
            ));
        }
    }

    @GetMapping("/api/config")
    public ResponseEntity<?> getConfig(@RequestHeader(value = "Authorization", defaultValue = "") String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> user = users.get(session.get("user_id"));
        if (user == null || !"admin".equals(user.get("role"))) {
            return ResponseEntity.status(403).body(Map.of("error", "Admin access required"));
        }

        return ResponseEntity.ok(Map.of(
            "database_url", DB_URL,
            "smtp_host", SMTP_HOST,
            "smtp_credential", SMTP_CREDENTIAL,
            "session_count", sessions.size(),
            "user_count", users.size()
        ));
    }

    @GetMapping("/api/debug/user/{userId}")
    public ResponseEntity<?> debugUser(@RequestHeader(value = "Authorization", defaultValue = "") String auth,
                                        @PathVariable int userId) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> user = users.get(userId);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        return ResponseEntity.ok(user);
    }

    @GetMapping("/api/health")
    public ResponseEntity<?> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "healthy", "service", "design-api"));
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
