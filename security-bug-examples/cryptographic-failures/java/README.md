# Cryptographic Failures - Java Example

## Prerequisites

- JDK 17+
- Maven 3.8+

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
java -jar target/crypto-service-1.0.0.jar
```

The application starts a Spring Boot API server on port 8097.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8097/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create an encrypted record:

```bash
curl -X POST http://localhost:8097/api/records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"content": "sensitive data here"}'
```

Retrieve a record:

```bash
curl http://localhost:8097/api/records/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Verify record integrity:

```bash
curl -X POST http://localhost:8097/api/records/1/verify \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Generate an API token:

```bash
curl -X POST http://localhost:8097/api/tokens/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"label": "my-token"}'
```

Hash data:

```bash
curl -X POST http://localhost:8097/api/hash \
  -H "Content-Type: application/json" \
  -d '{"value": "test", "algorithm": "md5"}'
```

Encrypt data:

```bash
curl -X POST http://localhost:8097/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "hello world"}'
```
