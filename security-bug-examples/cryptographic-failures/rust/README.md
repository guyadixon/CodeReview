# Cryptographic Failures - Rust Example

## Prerequisites

- Rust 1.70+ (via rustup)

Install Rust on Ubuntu/Debian:

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

The application starts an Actix-web API server on port 8099.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8099/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create an encrypted record:

```bash
curl -X POST http://localhost:8099/api/records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"content": "sensitive data here"}'
```

Retrieve a record:

```bash
curl http://localhost:8099/api/records/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Generate an API token:

```bash
curl -X POST http://localhost:8099/api/tokens/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"label": "my-token"}'
```

Hash data:

```bash
curl -X POST http://localhost:8099/api/hash \
  -H "Content-Type: application/json" \
  -d '{"value": "test", "algorithm": "md5"}'
```

Encrypt data:

```bash
curl -X POST http://localhost:8099/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "hello world"}'
```
