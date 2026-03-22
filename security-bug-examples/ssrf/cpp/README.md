# SSRF - C++ Example

## Prerequisites

- g++ or clang++ (C++17+)
- cpp-httplib (header-only, included)
- nlohmann/json (header-only, included)
- OpenSSL development headers

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make libssl-dev
```

## Build

```bash
make
```

## Run

```bash
./main
```

The application starts a cpp-httplib API server on port 9011.

## Test the Endpoints

Health check:

```bash
curl http://localhost:9011/api/health
```

Login:

```bash
curl -X POST http://localhost:9011/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

Fetch a URL (use token from login response):

```bash
curl -X POST http://localhost:9011/api/fetch-url \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"url": "https://httpbin.org/get"}'
```

Preview a link:

```bash
curl "http://localhost:9011/api/preview?target=https://example.com" \
  -H "Authorization: Bearer <token>"
```

Register a webhook:

```bash
curl -X POST http://localhost:9011/api/webhooks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"callback_url": "https://httpbin.org/post", "event_type": "deploy"}'
```

Test a webhook:

```bash
curl -X POST http://localhost:9011/api/webhooks/<webhook_id>/test \
  -H "Authorization: Bearer <token>"
```

Import configuration:

```bash
curl -X POST http://localhost:9011/api/integrations/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"config_url": "https://httpbin.org/json"}'
```

Proxy a service request:

```bash
curl "http://localhost:9011/api/proxy?service=analytics&path=/status" \
  -H "Authorization: Bearer <token>"
```
