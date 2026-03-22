# Security Misconfiguration - Java Example

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
mvn spring-boot:run
```

The application starts a Spring Boot API server on port 8080.

## Test the Endpoints

List products:

```bash
curl http://localhost:8080/api/products
```

Get a single product:

```bash
curl http://localhost:8080/api/products/1
```

Create a product:

```bash
curl -X POST http://localhost:8080/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Widget", "sku": "TW-001", "price": 19.99, "stock": 50}'
```

Import products via XML:

```bash
curl -X POST http://localhost:8080/api/products/import \
  -H "Content-Type: application/xml" \
  -d '<products><product><name>Imported Item</name><sku>II-100</sku><price>9.99</price><stock>25</stock></product></products>'
```

Import orders via XML:

```bash
curl -X POST http://localhost:8080/api/orders/import \
  -H "Content-Type: application/xml" \
  -d '<orders><order><customer>Alice</customer><product_sku>WP-100</product_sku><quantity>1</quantity><notes>Rush</notes></order></orders>'
```

Get settings:

```bash
curl http://localhost:8080/api/settings
```

Update settings:

```bash
curl -X PUT http://localhost:8080/api/settings \
  -H "Content-Type: application/json" \
  -d '{"maintenance_mode": true}'
```

Admin diagnostics:

```bash
curl http://localhost:8080/api/admin/diagnostics \
  -H "X-Admin-Token: super-admin-token-2024"
```

Admin environment:

```bash
curl http://localhost:8080/api/admin/env \
  -H "X-Admin-Token: super-admin-token-2024"
```

Health check:

```bash
curl http://localhost:8080/api/health
```
