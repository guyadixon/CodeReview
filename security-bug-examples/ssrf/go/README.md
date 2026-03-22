# SSRF - Go Example

## Prerequisites

- Go 1.21+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official Go website for the latest version.

## Install Dependencies

```bash
go mod download
```

## Build

```bash
go build -o gateway-api main.go
```

## Run

```bash
./gateway-api
```

The application starts a Gin API server on port 8010.

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
  -d '{"callback_url": "https://httpbin.org/post", "event_type": "deploy"}'
```

Test a webhook:

```bash
curl -X POST http://localhost:8010/api/webhooks/<webhook_id>/test \
  -H "Authorization: Bearer <token>"
```

Import configuration:

```bash
curl -X POST http://localhost:8010/api/integrations/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"config_url": "https://httpbin.org/json"}'
```

Proxy a service request:

```bash
curl "http://localhost:8010/api/proxy?service=analytics&path=/status" \
  -H "Authorization: Bearer <token>"
```
