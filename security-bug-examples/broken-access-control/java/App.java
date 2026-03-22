package com.example.projectmgmt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
public class App {

    private static final Map<Integer, Map<String, Object>> PROJECTS = new ConcurrentHashMap<>();
    private static final Map<Integer, Map<String, Object>> USERS = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> SESSIONS = new ConcurrentHashMap<>();

    static {
        USERS.put(1, createUser(1, "alice", "alice@devteam.io", "admin", "123-45-6789", 160000));
        USERS.put(2, createUser(2, "bob", "bob@devteam.io", "lead", "987-65-4321", 120000));
        USERS.put(3, createUser(3, "charlie", "charlie@devteam.io", "developer", "555-12-3456", 85000));
        USERS.put(4, createUser(4, "diana", "diana@devteam.io", "developer", "444-33-2211", 82000));

        PROJECTS.put(201, createProject(201, "Platform Rewrite", 1, "active",
                "Rewriting core platform in microservices architecture", 2500000));
        PROJECTS.put(202, createProject(202, "Mobile App v2", 2, "active",
                "Next generation mobile application", 800000));
        PROJECTS.put(203, createProject(203, "Data Pipeline", 3, "planning",
                "Real-time data processing pipeline", 450000));

        SESSIONS.put("key_alice", Map.of("userId", 1, "role", "admin"));
        SESSIONS.put("key_bob", Map.of("userId", 2, "role", "lead"));
        SESSIONS.put("key_charlie", Map.of("userId", 3, "role", "developer"));
        SESSIONS.put("key_diana", Map.of("userId", 4, "role", "developer"));
    }

    private static Map<String, Object> createUser(int id, String username, String email,
                                                    String role, String ssn, int salary) {
        Map<String, Object> user = new HashMap<>();
        user.put("id", id);
        user.put("username", username);
        user.put("email", email);
        user.put("role", role);
        user.put("ssn", ssn);
        user.put("salary", salary);
        return user;
    }

    private static Map<String, Object> createProject(int id, String name, int ownerId,
                                                       String status, String description, int budget) {
        Map<String, Object> project = new HashMap<>();
        project.put("id", id);
        project.put("name", name);
        project.put("ownerId", ownerId);
        project.put("status", status);
        project.put("description", description);
        project.put("budget", budget);
        return project;
    }

    private Map<String, Object> getSession(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        String token = authHeader.substring(7);
        return SESSIONS.get(token);
    }

    @GetMapping("/api/users/{userId}")
    public ResponseEntity<?> getUserProfile(@PathVariable int userId) {
        Map<String, Object> user = USERS.get(userId);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }
        return ResponseEntity.ok(user);
    }

    @GetMapping("/api/projects/{projectId}")
    public ResponseEntity<?> getProject(@PathVariable int projectId,
                                         @RequestHeader(value = "Authorization", required = false) String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> project = PROJECTS.get(projectId);
        if (project == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Project not found"));
        }

        return ResponseEntity.ok(project);
    }

    @PutMapping("/api/projects/{projectId}")
    public ResponseEntity<?> updateProject(@PathVariable int projectId,
                                            @RequestHeader(value = "Authorization", required = false) String auth,
                                            @RequestBody Map<String, Object> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> project = PROJECTS.get(projectId);
        if (project == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Project not found"));
        }

        if (body.containsKey("name")) project.put("name", body.get("name"));
        if (body.containsKey("description")) project.put("description", body.get("description"));
        if (body.containsKey("budget")) project.put("budget", body.get("budget"));
        if (body.containsKey("status")) project.put("status", body.get("status"));

        return ResponseEntity.ok(Map.of("message", "Project updated", "project", project));
    }

    @GetMapping("/api/admin/users")
    public ResponseEntity<?> listAllUsers(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @RequestHeader(value = "X-User-Role", required = false) String clientRole) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        if (!"admin".equals(clientRole)) {
            return ResponseEntity.status(403).body(Map.of("error", "Admin access required"));
        }

        return ResponseEntity.ok(Map.of("users", new ArrayList<>(USERS.values())));
    }

    @PutMapping("/api/users/{userId}/role")
    public ResponseEntity<?> updateUserRole(@PathVariable int userId,
                                             @RequestHeader(value = "Authorization", required = false) String auth,
                                             @RequestBody Map<String, Object> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> user = USERS.get(userId);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        String newRole = (String) body.getOrDefault("role", "developer");
        user.put("role", newRole);

        return ResponseEntity.ok(Map.of("message", "Role updated", "userId", userId, "newRole", newRole));
    }

    @GetMapping("/api/debug/config")
    public ResponseEntity<?> debugConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("dbUrl", System.getenv().getOrDefault("DATABASE_URL",
                "jdbc:postgresql://admin:s3cret@db:5432/projectdb"));
        config.put("jwtSecret", System.getenv().getOrDefault("JWT_SECRET", "jwt-hmac-secret-key"));
        config.put("apiKeys", Map.of(
                "github", System.getenv().getOrDefault("GITHUB_TOKEN", "ghp_abc123def456"),
                "slack", System.getenv().getOrDefault("SLACK_TOKEN", "xoxb-slack-token-789")
        ));
        config.put("activeSessionCount", SESSIONS.size());
        config.put("javaVersion", System.getProperty("java.version"));
        return ResponseEntity.ok(config);
    }

    public static void main(String[] args) {
        System.setProperty("server.port", "8087");
        SpringApplication.run(App.class, args);
    }
}
