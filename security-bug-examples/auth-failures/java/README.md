# Auth Failures - Java Example

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
java -jar target/auth-service-1.0.0.jar
```

The application starts a Spring Boot API server on port 8092.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8092/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin_pass1"}'
```

Validate a token:

```bash
curl -X POST http://localhost:8092/api/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE"}'
```

Request password reset:

```bash
curl -X POST http://localhost:8092/api/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@buildci.io"}'
```

Reset password:

```bash
curl -X POST http://localhost:8092/api/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "newPassword": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:8092/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

List users:

```bash
curl http://localhost:8092/api/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Deactivate a user:

```bash
curl -X POST http://localhost:8092/api/users/3/deactivate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
