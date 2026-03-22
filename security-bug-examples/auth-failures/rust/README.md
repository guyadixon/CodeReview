# Auth Failures - Rust Example

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

The application starts an Actix-web API server on port 8094.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8094/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin_pipe1"}'
```

Verify a token:

```bash
curl -X POST http://localhost:8094/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE"}'
```

Request password reset:

```bash
curl -X POST http://localhost:8094/api/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@pipeline.io"}'
```

Reset password:

```bash
curl -X POST http://localhost:8094/api/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "new_password": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:8094/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

List users:

```bash
curl http://localhost:8094/api/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Deactivate a user:

```bash
curl -X POST http://localhost:8094/api/users/3/deactivate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
