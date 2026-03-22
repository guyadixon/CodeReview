# Insecure Design - Go Example

## Prerequisites

- Go 1.21+

Install Go on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install the latest version from the official site:

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
go build -o design-api main.go
```

## Run

```bash
./design-api
```

The application starts a Gin API server on port 8087.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8087/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

Register a new user:

```bash
curl -X POST http://localhost:8087/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "email": "new@acmecorp.io", "password": "test123"}'
```

Request password reset:

```bash
curl -X POST http://localhost:8087/api/password-reset \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@acmecorp.io"}'
```

Confirm password reset:

```bash
curl -X POST http://localhost:8087/api/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "new_password": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:8087/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Change password:

```bash
curl -X PUT http://localhost:8087/api/users/me/password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"new_password": "updated_pass"}'
```

Generate report:

```bash
curl -X POST http://localhost:8087/api/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"type": "users"}'
```

Get config (admin only):

```bash
curl http://localhost:8087/api/config \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Debug user:

```bash
curl http://localhost:8087/api/debug/user/1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Health check:

```bash
curl http://localhost:8087/api/health
```

## External Service Setup

This application attempts to connect to a PostgreSQL database. To test the report generation endpoint, start a PostgreSQL instance:

```bash
docker run -d --name designdb \
  -e POSTGRES_USER=appuser \
  -e POSTGRES_PASSWORD=Pg_Pr0d#2024 \
  -e POSTGRES_DB=designdb \
  -p 5432:5432 postgres:15
```
