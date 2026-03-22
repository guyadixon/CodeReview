# Logging/Monitoring Failures - C Example

## Prerequisites

- GCC or Clang (C11+)
- libmicrohttpd development headers

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y gcc make libmicrohttpd-dev
```

## Build

```bash
make
```

## Run

```bash
./logging_api
```

The application starts a libmicrohttpd API server on port 9089. Press Enter to stop the server.

## Test the Endpoints

Health check:

```bash
curl http://localhost:9089/api/health
```

Login:

```bash
curl -X POST http://localhost:9089/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

List users (use token from login response):

```bash
curl http://localhost:9089/api/admin/users \
  -H "Authorization: Bearer <token>"
```

Create a transaction:

```bash
curl -X POST http://localhost:9089/api/transactions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"amount": 500.00, "recipient": "vendor@example.com", "description": "Payment"}'
```

Export data:

```bash
curl -X POST http://localhost:9089/api/export/data \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "users"}'
```

Regenerate API key:

```bash
curl -X POST http://localhost:9089/api/settings/api-key \
  -H "Authorization: Bearer <token>"
```
