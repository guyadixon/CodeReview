# Cryptographic Failures - C Example

## Prerequisites

- gcc (C11+)
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
./crypto-server
```

The application starts a libmicrohttpd API server on port 8100. Press Enter to stop the server.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8100/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin2024!"}'
```

Create an encrypted record:

```bash
curl -X POST http://localhost:8100/api/records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"content":"sensitive data here"}'
```

Retrieve a record:

```bash
curl http://localhost:8100/api/records/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Generate an API token:

```bash
curl -X POST http://localhost:8100/api/tokens/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"label":"my-token"}'
```

Hash data:

```bash
curl -X POST http://localhost:8100/api/hash \
  -H "Content-Type: application/json" \
  -d '{"value":"test","algorithm":"md5"}'
```

Encrypt data:

```bash
curl -X POST http://localhost:8100/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello world"}'
```
