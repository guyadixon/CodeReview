# Broken Access Control - Rust Example

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

The application starts an Actix-web API server on port 8089.

## Test the Endpoints

Get a user profile:

```bash
curl http://localhost:8089/api/users/1
```

Get an order:

```bash
curl http://localhost:8089/api/orders/401 \
  -H "Authorization: Bearer tok_charlie"
```

Update an order:

```bash
curl -X PUT http://localhost:8089/api/orders/402 \
  -H "Authorization: Bearer tok_diana" \
  -H "Content-Type: application/json" \
  -d '{"status": "shipped"}'
```

List all users (admin):

```bash
curl http://localhost:8089/api/admin/users \
  -H "Authorization: Bearer tok_alice" \
  -H "X-User-Role: admin"
```

Update a user's role:

```bash
curl -X PUT http://localhost:8089/api/users/3/role \
  -H "Authorization: Bearer tok_alice" \
  -H "Content-Type: application/json" \
  -d '{"role": "support"}'
```

Debug configuration:

```bash
curl http://localhost:8089/api/debug/config
```
