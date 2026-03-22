# Auth Failures - Go Example

## Prerequisites

- Go 1.21+

Install Go on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official site:

```bash
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

## Install Dependencies

```bash
go mod download
```

## Build

```bash
go build -o auth-server main.go
```

## Run

```bash
./auth-server
```

The application starts a Gin API server on port 8093.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8093/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin_ops1"}'
```

Verify a token:

```bash
curl -X POST http://localhost:8093/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE"}'
```

Request password reset:

```bash
curl -X POST http://localhost:8093/api/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@deployops.io"}'
```

Reset password:

```bash
curl -X POST http://localhost:8093/api/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "newPassword": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:8093/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

List users:

```bash
curl http://localhost:8093/api/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Deactivate a user:

```bash
curl -X POST http://localhost:8093/api/users/2/deactivate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
