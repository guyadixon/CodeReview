# Cryptographic Failures - Go Example

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
go build -o crypto-server main.go
```

## Run

```bash
./crypto-server
```

The application starts a Gin API server on port 8098.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8098/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create an encrypted record:

```bash
curl -X POST http://localhost:8098/api/records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"content": "sensitive data here"}'
```

Retrieve a record:

```bash
curl http://localhost:8098/api/records/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Verify record integrity:

```bash
curl -X POST http://localhost:8098/api/records/1/verify \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Generate an API token:

```bash
curl -X POST http://localhost:8098/api/tokens/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"label": "my-token"}'
```

Hash data:

```bash
curl -X POST http://localhost:8098/api/hash \
  -H "Content-Type: application/json" \
  -d '{"value": "test", "algorithm": "md5"}'
```

Encrypt data:

```bash
curl -X POST http://localhost:8098/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "hello world"}'
```
