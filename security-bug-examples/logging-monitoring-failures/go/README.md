# Logging/Monitoring Failures - Go Example

## Prerequisites

- Go 1.21+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official Go website:

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
go build -o logging-api main.go
```

## Run

```bash
./logging-api
```

The application starts a Gin API server on port 8089.

## Test the Endpoints

Health check:

```bash
curl http://localhost:8089/api/health
```

Login:

```bash
curl -X POST http://localhost:8089/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

List users (use token from login response):

```bash
curl http://localhost:8089/api/admin/users \
  -H "Authorization: Bearer <token>"
```

Create a transaction:

```bash
curl -X POST http://localhost:8089/api/transactions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"amount": 500.00, "recipient": "vendor@example.com", "description": "Payment"}'
```

Export data:

```bash
curl -X POST http://localhost:8089/api/export/data \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "users"}'
```

Regenerate API key:

```bash
curl -X POST http://localhost:8089/api/settings/api-key \
  -H "Authorization: Bearer <token>"
```
