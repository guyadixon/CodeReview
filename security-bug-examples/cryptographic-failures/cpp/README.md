# Cryptographic Failures - C++ Example

## Prerequisites

- g++ or clang++ (C++17+)
- cpp-httplib (header-only, included via system headers)
- nlohmann/json (header-only)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make nlohmann-json3-dev
```

Install cpp-httplib header:

```bash
sudo apt-get install -y libhttplib-dev
```

If `libhttplib-dev` is not available, download the header manually:

```bash
sudo mkdir -p /usr/include
sudo wget -O /usr/include/httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
```

## Build

```bash
make
```

## Run

```bash
./crypto-server
```

The application starts a cpp-httplib API server on port 8101.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8101/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin2024!"}'
```

Create an encrypted record:

```bash
curl -X POST http://localhost:8101/api/records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"content":"sensitive data here"}'
```

Retrieve a record:

```bash
curl http://localhost:8101/api/records/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Generate an API token:

```bash
curl -X POST http://localhost:8101/api/tokens/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"label":"my-token"}'
```

Hash data:

```bash
curl -X POST http://localhost:8101/api/hash \
  -H "Content-Type: application/json" \
  -d '{"value":"test","algorithm":"md5"}'
```

Encrypt data:

```bash
curl -X POST http://localhost:8101/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello world"}'
```
