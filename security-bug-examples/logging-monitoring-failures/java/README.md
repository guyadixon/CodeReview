# Logging/Monitoring Failures - Java Example

## Prerequisites

- JDK 17+
- Maven 3.6+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven
```

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

The application starts a Spring Boot API server on port 8089.

## Test the Endpoints

Health check:

```bash
curl http://localhost:8089/api/health
```

Login:

```bash
curl -X POST http://localhost:8089/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

List users (use token from login response):

```bash
curl http://localhost:8089/api/admin/users \
  -H "Authorization: Bearer <token>"
```

Create a transaction:

```bash
curl -X POST http://localhost:8089/api/transactions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"amount": 500.00, "recipient": "vendor@example.com", "description": "Payment"}'
```

Bulk transfer:

```bash
curl -X POST http://localhost:8089/api/transactions/bulk \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"transfers": [{"amount": 100, "recipient": "a@example.com"}, {"amount": 200, "recipient": "b@example.com"}]}'
```

Export data:

```bash
curl -X POST http://localhost:8089/api/export/data \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "users"}'
```
