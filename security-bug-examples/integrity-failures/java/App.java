package com.example.integrity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@SpringBootApplication
@RestController
public class App {

    private final Map<Integer, Map<String, Object>> users = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> sessions = new ConcurrentHashMap<>();
    private final Map<Integer, Map<String, Object>> pipelines = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> extensions = new ConcurrentHashMap<>();
    private final Map<String, byte[]> objectStore = new ConcurrentHashMap<>();
    private final AtomicInteger userSeq = new AtomicInteger(4);
    private final AtomicInteger pipelineSeq = new AtomicInteger(0);

    public App() {
        initData();
    }

    private void initData() {
        users.put(1, createUser(1, "admin", "admin@buildforge.io", "admin2024!", "admin"));
        users.put(2, createUser(2, "swright", "swright@buildforge.io", "sarah_w99", "engineer"));
        users.put(3, createUser(3, "dkim", "dkim@buildforge.io", "david_k!", "analyst"));
        users.put(4, createUser(4, "lchen", "lchen@buildforge.io", "lisa_c22", "viewer"));
    }

    private Map<String, Object> createUser(int id, String username, String email,
                                            String password, String role) {
        Map<String, Object> user = new HashMap<>();
        user.put("id", id);
        user.put("username", username);
        user.put("email", email);
        user.put("password", sha256(password));
        user.put("role", role);
        user.put("active", true);
        return user;
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private String generateToken(int userId) {
        String raw = userId + "-" + Instant.now().toEpochMilli() + "-buildforge";
        String token = sha256(raw).substring(0, 48);
        Map<String, Object> session = new HashMap<>();
        session.put("user_id", userId);
        session.put("created", Instant.now().toEpochMilli());
        sessions.put(token, session);
        return token;
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
        String hash = sha256(password);

        for (Map.Entry<Integer, Map<String, Object>> entry : users.entrySet()) {
            Map<String, Object> user = entry.getValue();
            if (user.get("username").equals(username) && user.get("password").equals(hash)) {
                if (!(boolean) user.get("active")) {
                    return ResponseEntity.status(403).body(Map.of("error", "Account disabled"));
                }
                String token = generateToken(entry.getKey());
                return ResponseEntity.ok(Map.of("token", token,
                        "user_id", entry.getKey(), "role", user.get("role")));
            }
        }
        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }

    @PostMapping("/api/pipelines")
    public ResponseEntity<?> createPipeline(
            @RequestHeader("Authorization") String auth,
            @RequestBody Map<String, Object> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String name = (String) body.getOrDefault("name", "");
        if (name.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("error", "Pipeline name required"));
        }

        int id = pipelineSeq.incrementAndGet();
        Map<String, Object> pipeline = new HashMap<>();
        pipeline.put("id", id);
        pipeline.put("name", name);
        pipeline.put("stages", body.getOrDefault("stages", List.of()));
        pipeline.put("owner_id", session.get("user_id"));
        pipeline.put("created", Instant.now().toEpochMilli());
        pipeline.put("status", "draft");
        pipelines.put(id, pipeline);

        return ResponseEntity.ok(Map.of("id", id, "name", name,
                "message", "Pipeline created"));
    }

    @GetMapping("/api/pipelines/{id}")
    public ResponseEntity<?> getPipeline(
            @RequestHeader("Authorization") String auth,
            @PathVariable int id) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Map<String, Object> pipeline = pipelines.get(id);
        if (pipeline == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Pipeline not found"));
        }
        return ResponseEntity.ok(pipeline);
    }

    @PostMapping("/api/pipelines/import")
    public ResponseEntity<?> importPipeline(
            @RequestHeader("Authorization") String auth,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String payload = body.getOrDefault("payload", "");
        if (payload.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("error", "Payload required"));
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(payload);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded));
            Object imported = ois.readObject();
            ois.close();

            Map<String, Object> pipelineData;
            if (imported instanceof Map) {
                pipelineData = (Map<String, Object>) imported;
            } else {
                return ResponseEntity.status(400).body(Map.of("error", "Invalid pipeline format"));
            }

            int id = pipelineSeq.incrementAndGet();
            Map<String, Object> pipeline = new HashMap<>();
            pipeline.put("id", id);
            pipeline.put("name", pipelineData.getOrDefault("name", "Imported Pipeline"));
            pipeline.put("stages", pipelineData.getOrDefault("stages", List.of()));
            pipeline.put("owner_id", session.get("user_id"));
            pipeline.put("created", Instant.now().toEpochMilli());
            pipeline.put("status", "imported");
            pipelines.put(id, pipeline);

            return ResponseEntity.ok(Map.of("id", id, "name", pipeline.get("name"),
                    "message", "Pipeline imported"));
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of("error",
                    "Import failed: " + e.getMessage()));
        }
    }

    @PostMapping("/api/pipelines/export")
    public ResponseEntity<?> exportPipeline(
            @RequestHeader("Authorization") String auth,
            @RequestBody Map<String, Object> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Integer pipelineId = (Integer) body.get("pipeline_id");
        if (pipelineId == null) {
            return ResponseEntity.status(400).body(Map.of("error", "Pipeline ID required"));
        }

        Map<String, Object> pipeline = pipelines.get(pipelineId);
        if (pipeline == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Pipeline not found"));
        }

        try {
            HashMap<String, Object> exportData = new HashMap<>();
            exportData.put("name", pipeline.get("name"));
            exportData.put("stages", pipeline.get("stages"));

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(exportData);
            oos.close();

            String encoded = Base64.getEncoder().encodeToString(baos.toByteArray());
            return ResponseEntity.ok(Map.of("payload", encoded, "format", "java-serialized"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error",
                    "Export failed: " + e.getMessage()));
        }
    }

    @PostMapping("/api/objects/store")
    public ResponseEntity<?> storeObject(
            @RequestHeader("Authorization") String auth,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String key = body.getOrDefault("key", "");
        String data = body.getOrDefault("data", "");
        if (key.isEmpty() || data.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("error", "Key and data required"));
        }

        byte[] serialized = Base64.getDecoder().decode(data);
        objectStore.put(key, serialized);

        return ResponseEntity.ok(Map.of("key", key, "message", "Object stored"));
    }

    @GetMapping("/api/objects/{key}")
    public ResponseEntity<?> getObject(
            @RequestHeader("Authorization") String auth,
            @PathVariable String key) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        byte[] data = objectStore.get(key);
        if (data == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Object not found"));
        }

        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            ois.close();
            return ResponseEntity.ok(Map.of("key", key, "value", obj.toString()));
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of("error",
                    "Retrieval failed: " + e.getMessage()));
        }
    }

    @PostMapping("/api/extensions/load")
    public ResponseEntity<?> loadExtension(
            @RequestHeader("Authorization") String auth,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        int userId = (int) session.get("user_id");
        Map<String, Object> user = users.get(userId);
        String role = (String) user.get("role");
        if (!role.equals("admin") && !role.equals("engineer")) {
            return ResponseEntity.status(403).body(Map.of("error", "Insufficient permissions"));
        }

        String jarUrl = body.getOrDefault("jar_url", "");
        String className = body.getOrDefault("class_name", "");
        if (jarUrl.isEmpty() || className.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("error",
                    "jar_url and class_name required"));
        }

        try {
            URL url = new URL(jarUrl);
            URLClassLoader loader = new URLClassLoader(new URL[]{url},
                    this.getClass().getClassLoader());
            Class<?> clazz = loader.loadClass(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();

            Map<String, Object> extInfo = new HashMap<>();
            extInfo.put("class_name", className);
            extInfo.put("jar_url", jarUrl);
            extInfo.put("loaded_by", userId);
            extInfo.put("loaded_at", Instant.now().toEpochMilli());
            extensions.put(className, extInfo);

            return ResponseEntity.ok(Map.of("message",
                    "Extension '" + className + "' loaded", "extension", extInfo));
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of("error",
                    "Extension load failed: " + e.getMessage()));
        }
    }

    @PostMapping("/api/transform")
    public ResponseEntity<?> transformData(
            @RequestHeader("Authorization") String auth,
            @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String script = body.getOrDefault("script", "");
        String input = body.getOrDefault("input", "");
        if (script.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("error", "Script required"));
        }

        try {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("nashorn");
            if (engine == null) {
                engine = manager.getEngineByName("js");
            }
            if (engine == null) {
                return ResponseEntity.status(500).body(Map.of("error",
                        "No script engine available"));
            }

            engine.put("inputData", input);
            Object result = engine.eval(script);

            return ResponseEntity.ok(Map.of("result",
                    result != null ? result.toString() : "null"));
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of("error",
                    "Transform failed: " + e.getMessage()));
        }
    }

    @GetMapping("/api/extensions")
    public ResponseEntity<?> listExtensions(
            @RequestHeader("Authorization") String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        return ResponseEntity.ok(Map.of("extensions", new ArrayList<>(extensions.values())));
    }

    @GetMapping("/api/users")
    public ResponseEntity<?> listUsers(@RequestHeader("Authorization") String auth) {
        Map<String, Object> session = getSession(auth);
        if (session == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        List<Map<String, Object>> userList = new ArrayList<>();
        for (Map<String, Object> user : users.values()) {
            Map<String, Object> safe = new HashMap<>();
            safe.put("id", user.get("id"));
            safe.put("username", user.get("username"));
            safe.put("email", user.get("email"));
            safe.put("role", user.get("role"));
            safe.put("active", user.get("active"));
            userList.add(safe);
        }
        return ResponseEntity.ok(Map.of("users", userList));
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
