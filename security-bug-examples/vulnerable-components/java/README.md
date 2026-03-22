# Vulnerable Components - Java Example

## Prerequisites

- JDK 17+
- Maven 3.6+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven
```

## Build

```bash
mvn clean package -DskipTests
```

## Run

```bash
java -jar target/vulnerable-components-service-1.0.0.jar
```

The application starts a Spring Boot API server on port 8080.

## Test the Endpoints

List products:

```bash
curl http://localhost:8080/api/products
```

Get a product:

```bash
curl http://localhost:8080/api/products/1
```

Filter by category:

```bash
curl "http://localhost:8080/api/products?category=electronics"
```

Create an order:

```bash
curl -X POST http://localhost:8080/api/orders \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": 2}], "email": "user@example.com"}'
```

Import inventory:

```bash
curl -X POST http://localhost:8080/api/inventory/import \
  -H "Content-Type: application/json" \
  -d '{"format": "json", "payload": {"products": [{"id": 1, "stock": 200}]}}'
```

Generate product label:

```bash
curl "http://localhost:8080/api/products/1/label"
```

Export inventory:

```bash
curl -X POST http://localhost:8080/api/inventory/export \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/inventory.json"}'
```

Health check:

```bash
curl http://localhost:8080/api/health
```
