package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.apache.commons.text.StringSubstitutor;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@SpringBootApplication
@RestController
public class App {

    private static final Logger logger = LogManager.getLogger(App.class);
    private static final ObjectMapper jsonMapper = new ObjectMapper();
    private static final XmlMapper xmlMapper = new XmlMapper();

    private static final Map<Integer, Map<String, Object>> products = new ConcurrentHashMap<>();
    private static final Map<Integer, Map<String, Object>> orders = new ConcurrentHashMap<>();
    private static final AtomicInteger orderCounter = new AtomicInteger(1000);

    private static final Map<String, Object> warehouseConfig = new ConcurrentHashMap<>();

    static {
        products.put(1, createProduct(1, "Widget Pro", 29.99, 150, "hardware"));
        products.put(2, createProduct(2, "Gadget Plus", 49.99, 75, "electronics"));
        products.put(3, createProduct(3, "Tool Kit Standard", 19.99, 200, "tools"));
        products.put(4, createProduct(4, "Sensor Array", 89.99, 30, "electronics"));
        products.put(5, createProduct(5, "Cable Bundle", 9.99, 500, "accessories"));

        warehouseConfig.put("location", "us-east-1");
        warehouseConfig.put("api_endpoint", "https://warehouse.internal.acmecorp.io/api/v2");
        warehouseConfig.put("max_batch_size", 50);
        warehouseConfig.put("retry_attempts", 3);
    }

    private static Map<String, Object> createProduct(int id, String name, double price,
                                                      int stock, String category) {
        Map<String, Object> product = new HashMap<>();
        product.put("id", id);
        product.put("name", name);
        product.put("price", price);
        product.put("stock", stock);
        product.put("category", category);
        return product;
    }

    @GetMapping("/api/products")
    public ResponseEntity<?> listProducts(@RequestParam(required = false) String category) {
        List<Map<String, Object>> result = products.values().stream()
                .filter(p -> category == null || category.equals(p.get("category")))
                .collect(Collectors.toList());
        logger.info("Listed {} products for category: {}", result.size(), category);
        return ResponseEntity.ok(Map.of("products", result, "total", result.size()));
    }

    @GetMapping("/api/products/{productId}")
    public ResponseEntity<?> getProduct(@PathVariable int productId) {
        Map<String, Object> product = products.get(productId);
        if (product == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Product not found"));
        }
        return ResponseEntity.ok(product);
    }

    @PostMapping("/api/orders")
    public ResponseEntity<?> createOrder(@RequestBody Map<String, Object> body) {
        List<Map<String, Object>> items = (List<Map<String, Object>>) body.get("items");
        if (items == null || items.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "At least one item required"));
        }

        List<Map<String, Object>> orderItems = new ArrayList<>();
        double total = 0.0;

        for (Map<String, Object> item : items) {
            int pid = ((Number) item.get("product_id")).intValue();
            int qty = item.containsKey("quantity") ? ((Number) item.get("quantity")).intValue() : 1;
            Map<String, Object> product = products.get(pid);
            if (product == null) {
                return ResponseEntity.status(404).body(Map.of("error", "Product " + pid + " not found"));
            }
            int stock = ((Number) product.get("stock")).intValue();
            if (stock < qty) {
                return ResponseEntity.badRequest().body(Map.of("error",
                        "Insufficient stock for " + product.get("name")));
            }
            product.put("stock", stock - qty);
            double subtotal = ((Number) product.get("price")).doubleValue() * qty;
            total += subtotal;
            orderItems.add(Map.of(
                    "product_id", pid, "name", product.get("name"),
                    "quantity", qty, "subtotal", Math.round(subtotal * 100.0) / 100.0
            ));
        }

        int orderId = orderCounter.incrementAndGet();
        Map<String, Object> order = new HashMap<>();
        order.put("id", orderId);
        order.put("items", orderItems);
        order.put("total", Math.round(total * 100.0) / 100.0);
        order.put("status", "confirmed");
        order.put("customer_email", body.getOrDefault("email", ""));
        orders.put(orderId, order);

        logger.info("Order {} created with total {}", orderId, total);
        return ResponseEntity.status(201).body(Map.of(
                "order_id", orderId, "total", Math.round(total * 100.0) / 100.0, "status", "confirmed"
        ));
    }

    @GetMapping("/api/orders/{orderId}")
    public ResponseEntity<?> getOrder(@PathVariable int orderId) {
        Map<String, Object> order = orders.get(orderId);
        if (order == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Order not found"));
        }
        return ResponseEntity.ok(order);
    }

    @PostMapping("/api/inventory/import")
    public ResponseEntity<?> importInventory(@RequestBody Map<String, Object> body) {
        String format = (String) body.getOrDefault("format", "json");
        Object payload = body.get("payload");
        if (payload == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Payload required"));
        }

        try {
            Map<String, Object> parsed;
            if ("xml".equals(format)) {
                parsed = xmlMapper.readValue(payload.toString(), Map.class);
            } else {
                parsed = jsonMapper.convertValue(payload, Map.class);
            }

            int updated = 0;
            List<Map<String, Object>> productList = (List<Map<String, Object>>) parsed.get("products");
            if (productList != null) {
                for (Map<String, Object> entry : productList) {
                    int pid = ((Number) entry.get("id")).intValue();
                    Map<String, Object> existing = products.get(pid);
                    if (existing != null) {
                        if (entry.containsKey("stock")) {
                            existing.put("stock", ((Number) entry.get("stock")).intValue());
                        }
                        if (entry.containsKey("price")) {
                            existing.put("price", ((Number) entry.get("price")).doubleValue());
                        }
                        updated++;
                    }
                }
            }

            return ResponseEntity.ok(Map.of("message", "Inventory updated", "updated_count", updated));
        } catch (Exception e) {
            logger.error("Import failed: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Import failed", "details", e.getMessage()));
        }
    }

    @GetMapping("/api/products/{productId}/label")
    public ResponseEntity<?> generateLabel(@PathVariable int productId,
                                            @RequestParam(defaultValue = "${name} - $${price}") String template) {
        Map<String, Object> product = products.get(productId);
        if (product == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Product not found"));
        }

        Map<String, String> values = new HashMap<>();
        values.put("name", product.get("name").toString());
        values.put("price", product.get("price").toString());
        values.put("category", product.get("category").toString());
        values.put("stock", product.get("stock").toString());

        StringSubstitutor sub = new StringSubstitutor(values);
        String label = sub.replace(template);

        return ResponseEntity.ok(Map.of("label", label, "product_id", productId));
    }

    @PostMapping("/api/inventory/export")
    public ResponseEntity<?> exportInventory(@RequestBody Map<String, String> body) {
        String path = body.getOrDefault("path", "/tmp/inventory_export.json");

        try {
            String data = jsonMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(Map.of("products", products.values()));
            FileUtils.writeStringToFile(new File(path), data, StandardCharsets.UTF_8);
            return ResponseEntity.ok(Map.of("message", "Exported", "path", path, "products", products.size()));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Export failed", "details", e.getMessage()));
        }
    }

    @GetMapping("/api/config/warehouse")
    public ResponseEntity<?> getWarehouseConfig() {
        return ResponseEntity.ok(warehouseConfig);
    }

    @GetMapping("/api/health")
    public ResponseEntity<?> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "healthy", "service", "inventory-api"));
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
