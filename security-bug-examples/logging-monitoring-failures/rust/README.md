# Logging/Monitoring Failures - Rust Example

## Prerequisites

- Rust 1.70+ (via rustup)

Install on Ubuntu/Debian:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Install Dependencies

```bash
cargo fetch
```

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run --release
```

The application starts an Actix-web API server on port 8099.

## Test the Endpoints

Health check:

```bash
curl http://localhost:8099/api/health
```

Login:

```bash
curl -X POST http://localhost:8099/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

List users (use token from login response):

```bash
curl http://localhost:8099/api/admin/users \
  -H "Authorization: Bearer <token>"
```

Create a transaction:

```bash
curl -X POST http://localhost:8099/api/transactions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"amount": 500.00, "recipient": "vendor@example.com", "description": "Payment"}'
```

Export data:

```bash
curl -X POST http://localhost:8099/api/export/data \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "users"}'
```

Toggle MFA:

```bash
curl -X PUT http://localhost:8099/api/settings/mfa \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"enabled": false}'
```
