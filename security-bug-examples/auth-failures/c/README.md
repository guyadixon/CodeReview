# Auth Failures - C Example

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
./auth-server
```

The application starts a libmicrohttpd API server on port 8095. Press Enter to stop the server.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8095/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin_net1"}'
```

Verify a token:

```bash
curl -X POST http://localhost:8095/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"YOUR_TOKEN_HERE"}'
```

Request password reset:

```bash
curl -X POST http://localhost:8095/api/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@netmon.io"}'
```

Reset password:

```bash
curl -X POST http://localhost:8095/api/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token":"RESET_TOKEN","newPassword":"newpass123"}'
```

Get current user:

```bash
curl http://localhost:8095/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

List users:

```bash
curl http://localhost:8095/api/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
