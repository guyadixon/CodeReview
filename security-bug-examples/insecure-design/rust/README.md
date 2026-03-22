# Insecure Design - Rust Example

## Prerequisites

- Rust 1.70+
- Cargo (included with Rust)

Install Rust on Ubuntu/Debian:

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

The application starts an Actix-web API server on port 8097.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8097/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

Register a new user:

```bash
curl -X POST http://localhost:8097/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "email": "new@acmecorp.io", "password": "test123"}'
```

Request password reset:

```bash
curl -X POST http://localhost:8097/api/password-reset \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@acmecorp.io"}'
```

Confirm password reset:

```bash
curl -X POST http://localhost:8097/api/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "new_password": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:8097/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Change password:

```bash
curl -X PUT http://localhost:8097/api/users/me/password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"new_password": "updated_pass"}'
```

Generate report:

```bash
curl -X POST http://localhost:8097/api/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"type": "users"}'
```

Get config (admin only):

```bash
curl http://localhost:8097/api/config \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Debug user:

```bash
curl http://localhost:8097/api/debug/user/1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Health check:

```bash
curl http://localhost:8097/api/health
```
