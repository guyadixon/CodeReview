# Broken Access Control - Java Example

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
java -jar target/project-mgmt-api-1.0.0.jar
```

The application starts a Spring Boot API server on port 8087.

## Test the Endpoints

Get a user profile:

```bash
curl http://localhost:8087/api/users/1
```

Get a project:

```bash
curl http://localhost:8087/api/projects/201 \
  -H "Authorization: Bearer key_alice"
```

Update a project:

```bash
curl -X PUT http://localhost:8087/api/projects/202 \
  -H "Authorization: Bearer key_bob" \
  -H "Content-Type: application/json" \
  -d '{"name": "Mobile App v3", "budget": 900000}'
```

List all users (admin):

```bash
curl http://localhost:8087/api/admin/users \
  -H "Authorization: Bearer key_alice" \
  -H "X-User-Role: admin"
```

Update a user's role:

```bash
curl -X PUT http://localhost:8087/api/users/3/role \
  -H "Authorization: Bearer key_alice" \
  -H "Content-Type: application/json" \
  -d '{"role": "lead"}'
```

Debug configuration:

```bash
curl http://localhost:8087/api/debug/config
```
