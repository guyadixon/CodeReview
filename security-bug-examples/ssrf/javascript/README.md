# SSRF - JavaScript Example

## Prerequisites

- Node.js 18+
- npm

Install on Ubuntu/Debian:

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

## Install Dependencies

```bash
npm install
```

## Run

```bash
node app.js
```

The application starts an Express.js API server on port 3010.

## Test the Endpoints

Health check:

```bash
curl http://localhost:3010/api/health
```

Login:

```bash
curl -X POST http://localhost:3010/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

Fetch a URL (use token from login response):

```bash
curl -X POST http://localhost:3010/api/fetch-url \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"url": "https://httpbin.org/get"}'
```

Preview a link:

```bash
curl "http://localhost:3010/api/preview?target=https://example.com" \
  -H "Authorization: Bearer <token>"
```

Register a webhook:

```bash
curl -X POST http://localhost:3010/api/webhooks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"callbackUrl": "https://httpbin.org/post", "eventType": "deploy"}'
```

Test a webhook:

```bash
curl -X POST http://localhost:3010/api/webhooks/<webhook_id>/test \
  -H "Authorization: Bearer <token>"
```

Import configuration:

```bash
curl -X POST http://localhost:3010/api/integrations/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"configUrl": "https://httpbin.org/json"}'
```

Proxy a service request:

```bash
curl "http://localhost:3010/api/proxy?service=analytics&path=/status" \
  -H "Authorization: Bearer <token>"
```
