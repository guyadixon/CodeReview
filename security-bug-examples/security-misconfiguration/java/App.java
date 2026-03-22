package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@SpringBootApplication
@RestController
public class App {

    private static final String ADMIN_TOKEN = "super-admin-token-2024";
    private static final String DB_URL = "jdbc:postgresql://db.internal.acmecorp.io:5432/configdb";
    private static final String DB_USER = "appuser";
    private static final String DB_PASS = "Pg_Pr0d#2024";

    private static final Map<Integer, Map<String, Object>> products = new ConcurrentHashMap<>();
    private static final AtomicInteger nextId = new AtomicInteger(4);

    private static final Map<String, Object> settings = new ConcurrentHashMap<>();

    static {
        products.put(1, createProduct(1, "Widget Pro", "WP-100", 29.99, 150));
        products.put(2, createProduct(2, "Gadget Plus", "GP-200", 49.99, 75));
        products.put(3, createProduct(3, "Connector Kit", "CK-300", 14.99, 300));

        settings.put("maintenance_mode", false);
        settings.put("max_upload_size", 10485760);
        settings.put("allowed_origins", "*");
        settings.put("session_timeout", 86400);
        settings.put("rate_limit", 0);
        settings.put("log_level", "DEBUG");
        settings.put("enable_profiling", true);
        settings.put("tls_verify", false);
    }

    private static Map<String, Object> createProduct(int id, String name, String sku, double price, int stock) {
        Map<String, Object> p = new HashMap<>();
        p.put("id", id);
        p.put("name", name);
        p.put("sku", sku);
        p.put("price", price);
        p.put("stock", stock);
        return p;
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOriginPatterns("*")
                        .allowedMethods("*")
                        .allowedHeaders("*")
                        .allowCredentials(true);
            }
        };
    }

    @GetMapping("/api/products")
    public ResponseEntity<?> listProducts() {
        return ResponseEntity.ok(Map.of("products", new ArrayList<>(products.values())));
    }

    @GetMapping("/api/products/{id}")
    public ResponseEntity<?> getProduct(@PathVariable int id) {
        Map<String, Object> product = products.get(id);
        if (product == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Product not found"));
        }
        return ResponseEntity.ok(product);
    }

    @PostMapping("/api/products")
    public ResponseEntity<?> createProduct(@RequestBody Map<String, Object> body) {
        String name = (String) body.getOrDefault("name", "");
        if (name.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Product name required"));
        }

        int id = nextId.getAndIncrement();
        Map<String, Object> product = createProduct(
                id, name,
                (String) body.getOrDefault("sku", ""),
                body.containsKey("price") ? ((Number) body.get("price")).doubleValue() : 0,
                body.containsKey("stock") ? ((Number) body.get("stock")).intValue() : 0
        );
        products.put(id, product);
        return ResponseEntity.status(201).body(product);
    }

    @PostMapping(value = "/api/products/import", consumes = {"application/xml", "text/xml"})
    public ResponseEntity<?> importProducts(@RequestBody String xmlData) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setExpandEntityReferences(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));

            List<Map<String, Object>> imported = new ArrayList<>();
            NodeList items = doc.getElementsByTagName("product");

            for (int i = 0; i < items.getLength(); i++) {
                Element elem = (Element) items.item(i);
                int id = nextId.getAndIncrement();
                String name = getElementText(elem, "name");
                String sku = getElementText(elem, "sku");
                double price = parseDoubleOrDefault(getElementText(elem, "price"), 0);
                int stock = parseIntOrDefault(getElementText(elem, "stock"), 0);

                Map<String, Object> product = createProduct(id, name, sku, price, stock);
                products.put(id, product);
                imported.add(product);
            }

            return ResponseEntity.ok(Map.of("imported", imported, "count", imported.size()));

        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "XML parsing failed",
                    "details", e.getMessage(),
                    "trace", sw.toString()
            ));
        }
    }

    @PostMapping(value = "/api/orders/import", consumes = {"application/xml", "text/xml"})
    public ResponseEntity<?> importOrders(@RequestBody String xmlData) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));

            List<Map<String, Object>> orders = new ArrayList<>();
            NodeList orderNodes = doc.getElementsByTagName("order");

            for (int i = 0; i < orderNodes.getLength(); i++) {
                Element elem = (Element) orderNodes.item(i);
                Map<String, Object> order = new HashMap<>();
                order.put("customer", getElementText(elem, "customer"));
                order.put("product_sku", getElementText(elem, "product_sku"));
                order.put("quantity", parseIntOrDefault(getElementText(elem, "quantity"), 1));
                order.put("notes", getElementText(elem, "notes"));
                orders.add(order);
            }

            return ResponseEntity.ok(Map.of("orders", orders, "count", orders.size()));

        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Order import failed",
                    "details", e.getMessage(),
                    "trace", sw.toString()
            ));
        }
    }

    @GetMapping("/api/settings")
    public ResponseEntity<?> getSettings() {
        return ResponseEntity.ok(settings);
    }

    @PutMapping("/api/settings")
    public ResponseEntity<?> updateSettings(@RequestBody Map<String, Object> body) {
        settings.putAll(body);
        return ResponseEntity.ok(Map.of("message", "Settings updated", "settings", settings));
    }

    @GetMapping("/api/admin/diagnostics")
    public ResponseEntity<?> diagnostics(@RequestHeader(value = "X-Admin-Token", defaultValue = "") String token) {
        if (!ADMIN_TOKEN.equals(token)) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        Map<String, Object> info = new HashMap<>();
        info.put("database_url", DB_URL);
        info.put("database_user", DB_USER);
        info.put("database_password", DB_PASS);
        info.put("settings", settings);
        info.put("java_version", System.getProperty("java.version"));
        info.put("os_name", System.getProperty("os.name"));
        info.put("user_dir", System.getProperty("user.dir"));
        info.put("classpath", System.getProperty("java.class.path"));
        return ResponseEntity.ok(info);
    }

    @GetMapping("/api/admin/env")
    public ResponseEntity<?> getEnvironment(@RequestHeader(value = "X-Admin-Token", defaultValue = "") String token) {
        if (!ADMIN_TOKEN.equals(token)) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }
        return ResponseEntity.ok(Map.of("env", System.getenv()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return ResponseEntity.status(500).body(Map.of(
                "error", e.getClass().getSimpleName(),
                "message", e.getMessage() != null ? e.getMessage() : "",
                "trace", sw.toString()
        ));
    }

    @GetMapping("/api/health")
    public ResponseEntity<?> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "healthy", "service", "config-api"));
    }

    private String getElementText(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) {
            return nodes.item(0).getTextContent();
        }
        return "";
    }

    private double parseDoubleOrDefault(String s, double def) {
        try { return Double.parseDouble(s); } catch (Exception e) { return def; }
    }

    private int parseIntOrDefault(String s, int def) {
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
