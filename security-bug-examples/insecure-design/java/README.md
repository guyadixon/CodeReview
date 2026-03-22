# Insecure Design - Java Example

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

The application starts a Spring Boot API server on port 8080.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

Register a new user:

```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "email": "new@acmecorp.io", "password": "test123"}'
```

Request password reset:

```bash
curl -X POST http://localhost:8080/api/password-reset \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@acmecorp.io"}'
```

Confirm password reset:

```bash
curl -X POST http://localhost:8080/api/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "new_password": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:8080/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Change password:

```bash
curl -X PUT http://localhost:8080/api/users/me/password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"new_password": "updated_pass"}'
```

Generate report:

```bash
curl -X POST http://localhost:8080/api/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"type": "users"}'
```

Get config (admin only):

```bash
curl http://localhost:8080/api/config \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Debug user:

```bash
curl http://localhost:8080/api/debug/user/1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Health check:

```bash
curl http://localhost:8080/api/health
```
