# SQL Injection - Java Example

## Prerequisites

- JDK 17+
- Apache Maven 3.8+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven
```

## Project Structure

The source file uses Spring Boot with an embedded H2 database. The Maven `pom.xml` manages all dependencies.

## Install Dependencies

```bash
mvn dependency:resolve
```

## Build

```bash
mvn clean package -DskipTests
```

## Run

```bash
mvn spring-boot:run
```

Or run the packaged JAR:

```bash
java -jar target/sql-injection-demo-1.0.0.jar
```

The application starts a Spring Boot API server on port 8080.

## Test the Endpoints

Create a product:

```bash
curl -X POST http://localhost:8080/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Laptop", "category": "electronics", "price": 999.99, "stock": 10}'
```

Search products:

```bash
curl "http://localhost:8080/api/products/search?q=Laptop"
```

List products with sorting:

```bash
curl "http://localhost:8080/api/products?sort=price&order=DESC"
```

List products by category:

```bash
curl "http://localhost:8080/api/products?category=electronics"
```

Create a customer:

```bash
curl -X POST http://localhost:8080/api/customers \
  -H "Content-Type: application/json" \
  -d '{"username": "jdoe", "email": "jdoe@example.com"}'
```

Create an order:

```bash
curl -X POST http://localhost:8080/api/orders \
  -H "Content-Type: application/json" \
  -d '{"customer_id": 1, "product_id": 1, "quantity": 2}'
```

List orders:

```bash
curl "http://localhost:8080/api/orders?customerId=1&status=pending"
```

Delete products by category:

```bash
curl -X DELETE "http://localhost:8080/api/products?category=electronics"
```
