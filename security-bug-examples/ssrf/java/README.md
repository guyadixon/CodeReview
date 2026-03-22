# SSRF - Java Example

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
java -jar target/gateway-api-1.0.0.jar
```

The application starts a Spring Boot API server on port 8010.

## Test the Endpoints

Health check:

```bash
curl http://localhost:8010/api/health
```

Login:

```bash
curl -X POST http://localhost:8010/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

Fetch a URL (use token from login response):

```bash
curl -X POST http://localhost:8010/api/fetch-url \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"url": "https://httpbin.org/get"}'
```

Preview a link:

```bash
curl "http://localhost:8010/api/preview?target=https://example.com" \
  -H "Authorization: Bearer <token>"
```

Register a webhook:

```bash
curl -X POST http://localhost:8010/api/webhooks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"callbackUrl": "https://httpbin.org/post", "eventType": "deploy"}'
```

Test a webhook:

```bash
curl -X POST http://localhost:8010/api/webhooks/<webhookId>/test \
  -H "Authorization: Bearer <token>"
```

Import configuration:

```bash
curl -X POST http://localhost:8010/api/integrations/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"configUrl": "https://httpbin.org/json"}'
```

Proxy a service request:

```bash
curl "http://localhost:8010/api/proxy?service=analytics&path=/status" \
  -H "Authorization: Bearer <token>"
```
