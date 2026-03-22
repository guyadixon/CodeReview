# Integrity Failures - Java Example

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
java -jar target/integrity-service-1.0.0.jar
```

The application starts a Spring Boot API server on port 8080.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create a pipeline:

```bash
curl -X POST http://localhost:8080/api/pipelines \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name": "build-pipeline", "stages": ["compile", "test", "deploy"]}'
```

Import a pipeline:

```bash
curl -X POST http://localhost:8080/api/pipelines/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"payload": "BASE64_ENCODED_SERIALIZED_OBJECT"}'
```

Export a pipeline:

```bash
curl -X POST http://localhost:8080/api/pipelines/export \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"pipeline_id": 1}'
```

Store an object:

```bash
curl -X POST http://localhost:8080/api/objects/store \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"key": "config-v1", "data": "BASE64_ENCODED_DATA"}'
```

Retrieve an object:

```bash
curl http://localhost:8080/api/objects/config-v1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Transform data:

```bash
curl -X POST http://localhost:8080/api/transform \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"script": "inputData.toUpperCase()", "input": "hello world"}'
```

List users:

```bash
curl http://localhost:8080/api/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```
