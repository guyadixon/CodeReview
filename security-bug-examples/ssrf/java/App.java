package com.example.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@RestController
public class App {

    private static final Map<Integer, Map<String, Object>> users = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> sessions = new ConcurrentHashMap<>();
    private static final Map<String, Map<String, Object>> webhookRegistry = new ConcurrentHashMap<>();

    static {
        users.put(1, createUser(1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", true, "ak-admin-x7k9m2"));
        users.put(2, createUser(2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", true, "ak-jdoe-p3q8r1"));
        users.put(3, createUser(3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", true, "ak-asmith-w5t6y4"));
    }

    private static Map<String, Object> createUser(int id, String username, String email,
                                                    String password, String role, boolean active, String apiKey) {
        Map<String, Object> user = new HashMap<>();
        user.put("id", id);
        user.put("username", username);
        user.put("email", email);
        user.put("password", password);
        user.put("role", role);
        user.put("active", active);
        user.put("apiKey", apiKey);
        return user;
    }

    private String createSession(int userId) {
        try {
            String raw = userId + "-" + System.currentTimeMillis();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i++) sb.append(String.format("%02x", hash[i]));
            String token = sb.toString();
            Map<String, Object> session = new HashMap<>();
            session.put("userId", userId);
            session.put("created", System.currentTimeMillis());
            sessions.put(token, session);
            return token;
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }

    private Map<String, Object> getSession(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return sessions.get(authHeader.substring(7));
        }
        return null;
    }

    private String fetchRemoteContent(String targetUrl) throws IOException {
        URL url = new URL(targetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setInstanceFollowRedirects(true);

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            return content.toString();
        }
    }

    @PostMapping("/api/login")
    public Map<String, Object> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        for (Map.Entry<Integer, Map<String, Object>> entry : users.entrySet()) {
            Map<String, Object> user = entry.getValue();
            if (user.get("username").equals(username) && user.get("password").equals(password)) {
                if (!(boolean) user.get("active")) {
                    return Map.of("error", "Account disabled");
                }
                String token = createSession(entry.getKey());
                return Map.of("token", token, "userId", entry.getKey(), "role", user.get("role"));
            }
        }
        return Map.of("error", "Invalid credentials");
    }

    @PostMapping("/api/fetch-url")
    public Map<String, Object> fetchUrl(@RequestHeader(value = "Authorization", required = false) String auth,
                                         @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) return Map.of("error", "Authentication required");

        String url = body.getOrDefault("url", "");
        if (url.isEmpty()) return Map.of("error", "URL parameter required");

        try {
            String content = fetchRemoteContent(url);
            return Map.of(
                "status", 200,
                "contentLength", content.length(),
                "body", content.substring(0, Math.min(content.length(), 5000))
            );
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    @GetMapping("/api/preview")
    public Map<String, Object> previewLink(@RequestHeader(value = "Authorization", required = false) String auth,
                                            @RequestParam(defaultValue = "") String target) {
        Map<String, Object> session = getSession(auth);
        if (session == null) return Map.of("error", "Authentication required");

        if (target.isEmpty()) return Map.of("error", "target parameter required");

        try {
            URI uri = new URI(target);
            List<String> blockedHosts = List.of("localhost", "127.0.0.1");
            if (blockedHosts.contains(uri.getHost())) {
                return Map.of("error", "Blocked host");
            }

            String content = fetchRemoteContent(target);
            return Map.of(
                "url", target,
                "preview", content.substring(0, Math.min(content.length(), 2000))
            );
        } catch (URISyntaxException e) {
            return Map.of("error", "Invalid URL");
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    @PostMapping("/api/webhooks")
    public Map<String, Object> registerWebhook(@RequestHeader(value = "Authorization", required = false) String auth,
                                                @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) return Map.of("error", "Authentication required");

        String callbackUrl = body.getOrDefault("callbackUrl", "");
        String eventType = body.getOrDefault("eventType", "default");

        if (callbackUrl.isEmpty()) return Map.of("error", "callbackUrl required");

        try {
            URI uri = new URI(callbackUrl);
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) {
                return Map.of("error", "Only HTTP(S) callbacks supported");
            }
        } catch (URISyntaxException e) {
            return Map.of("error", "Invalid URL");
        }

        String webhookId = UUID.randomUUID().toString().substring(0, 12);
        Map<String, Object> webhook = new HashMap<>();
        webhook.put("id", webhookId);
        webhook.put("callbackUrl", callbackUrl);
        webhook.put("eventType", eventType);
        webhook.put("userId", session.get("userId"));
        webhook.put("created", System.currentTimeMillis());
        webhookRegistry.put(webhookId, webhook);

        return Map.of("message", "Webhook registered", "webhookId", webhookId);
    }

    @PostMapping("/api/webhooks/{webhookId}/test")
    public Map<String, Object> testWebhook(@RequestHeader(value = "Authorization", required = false) String auth,
                                            @PathVariable String webhookId) {
        Map<String, Object> session = getSession(auth);
        if (session == null) return Map.of("error", "Authentication required");

        Map<String, Object> webhook = webhookRegistry.get(webhookId);
        if (webhook == null) return Map.of("error", "Webhook not found");

        String callbackUrl = (String) webhook.get("callbackUrl");
        String payload = "{\"event\":\"test\",\"timestamp\":" + System.currentTimeMillis() + "}";

        try {
            URL url = new URL(callbackUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setRequestProperty("Content-Type", "application/json");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes(StandardCharsets.UTF_8));
            }

            int status = conn.getResponseCode();
            return Map.of("message", "Webhook delivered", "status", status);
        } catch (Exception e) {
            return Map.of("error", "Delivery failed: " + e.getMessage());
        }
    }

    @PostMapping("/api/integrations/import")
    public Map<String, Object> importConfig(@RequestHeader(value = "Authorization", required = false) String auth,
                                             @RequestBody Map<String, String> body) {
        Map<String, Object> session = getSession(auth);
        if (session == null) return Map.of("error", "Authentication required");

        String configUrl = body.getOrDefault("configUrl", "");
        if (configUrl.isEmpty()) return Map.of("error", "configUrl required");

        try {
            URI uri = new URI(configUrl);
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) {
                return Map.of("error", "Only HTTP(S) URLs supported");
            }

            String host = uri.getHost();
            if (host != null && host.startsWith("169.254")) {
                return Map.of("error", "Metadata endpoints not allowed");
            }

            String content = fetchRemoteContent(configUrl);
            return Map.of("message", "Configuration imported", "rawConfig", content.substring(0, Math.min(content.length(), 5000)));
        } catch (URISyntaxException e) {
            return Map.of("error", "Invalid URL");
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    @GetMapping("/api/proxy")
    public Map<String, Object> proxyRequest(@RequestHeader(value = "Authorization", required = false) String auth,
                                             @RequestParam(defaultValue = "") String service,
                                             @RequestParam(defaultValue = "/") String path,
                                             @RequestParam(defaultValue = "") String baseUrl) {
        Map<String, Object> session = getSession(auth);
        if (session == null) return Map.of("error", "Authentication required");

        Map<String, String> serviceMap = Map.of(
            "analytics", "http://analytics-service:8081",
            "billing", "http://billing-service:8082",
            "notifications", "http://notifications-service:8083"
        );

        String resolvedBase = serviceMap.getOrDefault(service, "");
        if (resolvedBase.isEmpty()) {
            resolvedBase = baseUrl;
            if (resolvedBase.isEmpty()) return Map.of("error", "Unknown service");
        }

        String fullUrl = resolvedBase + path;

        try {
            String content = fetchRemoteContent(fullUrl);
            return Map.of("status", 200, "body", content.substring(0, Math.min(content.length(), 5000)));
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    @GetMapping("/api/health")
    public Map<String, Object> healthCheck() {
        return Map.of("status", "healthy", "service", "gateway-api");
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
