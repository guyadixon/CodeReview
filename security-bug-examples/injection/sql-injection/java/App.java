package com.example.inventory;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import jakarta.annotation.PostConstruct;
import java.util.*;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class App {

    private final JdbcTemplate jdbc;

    public App(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostConstruct
    public void initSchema() {
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                category VARCHAR(100) NOT NULL,
                price DECIMAL(10,2) NOT NULL,
                stock INT DEFAULT 0
            )
        """);
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) NOT NULL,
                membership_tier VARCHAR(50) DEFAULT 'basic'
            )
        """);
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                customer_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """);
    }

    @GetMapping("/products/search")
    public ResponseEntity<?> searchProducts(@RequestParam String q) {
        String sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%'";
        List<Map<String, Object>> results = jdbc.queryForList(sql);
        return ResponseEntity.ok(results);
    }

    @GetMapping("/products")
    public ResponseEntity<?> listProducts(
            @RequestParam(required = false) String category,
            @RequestParam(defaultValue = "name") String sort,
            @RequestParam(defaultValue = "ASC") String order) {

        Set<String> allowedColumns = Set.of("name", "price", "stock", "category");
        if (!allowedColumns.contains(sort)) {
            sort = "name";
        }

        String sql;
        if (category != null && !category.isEmpty()) {
            sql = "SELECT * FROM products WHERE category = '" + category
                    + "' ORDER BY " + sort + " " + order;
        } else {
            sql = "SELECT * FROM products ORDER BY " + sort + " " + order;
        }

        List<Map<String, Object>> products = jdbc.queryForList(sql);
        return ResponseEntity.ok(products);
    }

    @GetMapping("/orders")
    public ResponseEntity<?> listOrders(
            @RequestParam int customerId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String dateFrom,
            @RequestParam(required = false) String dateTo) {

        StringBuilder sql = new StringBuilder(
                "SELECT o.*, p.name as product_name FROM orders o "
                        + "JOIN products p ON o.product_id = p.id "
                        + "WHERE o.customer_id = ?");

        List<Object> params = new ArrayList<>();
        params.add(customerId);

        if (status != null && !status.isEmpty()) {
            sql.append(" AND o.status = '").append(status).append("'");
        }

        if (dateFrom != null && !dateFrom.isEmpty()) {
            sql.append(" AND o.created_at >= '").append(dateFrom).append("'");
        }
        if (dateTo != null && !dateTo.isEmpty()) {
            sql.append(" AND o.created_at <= '").append(dateTo).append("'");
        }

        List<Map<String, Object>> orders = jdbc.queryForList(sql.toString(),
                params.toArray());
        return ResponseEntity.ok(orders);
    }

    @GetMapping("/customers/{id}")
    public ResponseEntity<?> getCustomer(@PathVariable int id) {
        List<Map<String, Object>> results = jdbc.queryForList(
                "SELECT * FROM customers WHERE id = ?", id);
        if (results.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Customer not found"));
        }
        return ResponseEntity.ok(results.get(0));
    }

    @PostMapping("/products")
    public ResponseEntity<?> createProduct(@RequestBody Map<String, Object> data) {
        jdbc.update(
                "INSERT INTO products (name, category, price, stock) VALUES (?, ?, ?, ?)",
                data.get("name"), data.get("category"),
                data.get("price"), data.getOrDefault("stock", 0));
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "Product created"));
    }

    @PostMapping("/customers")
    public ResponseEntity<?> createCustomer(@RequestBody Map<String, Object> data) {
        try {
            jdbc.update("INSERT INTO customers (username, email) VALUES (?, ?)",
                    data.get("username"), data.get("email"));
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("message", "Customer created"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "Username already exists"));
        }
    }

    @PostMapping("/orders")
    public ResponseEntity<?> createOrder(@RequestBody Map<String, Object> data) {
        jdbc.update(
                "INSERT INTO orders (customer_id, product_id, quantity) VALUES (?, ?, ?)",
                data.get("customer_id"), data.get("product_id"), data.get("quantity"));
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "Order created"));
    }

    @DeleteMapping("/products")
    public ResponseEntity<?> deleteProductsByCategory(@RequestParam String category) {
        String sql = "DELETE FROM products WHERE category = '" + category + "'";
        int deleted = jdbc.update(sql);
        return ResponseEntity.ok(Map.of("deleted", deleted));
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
