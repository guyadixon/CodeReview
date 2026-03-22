# SSRF - Rust Example

## Prerequisites

- Rust 1.70+
- Cargo

Install on Ubuntu/Debian:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run --release
```

The application starts an Actix-web API server on port 8010.

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
