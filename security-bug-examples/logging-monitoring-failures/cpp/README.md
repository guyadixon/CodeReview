# Logging/Monitoring Failures - C++ Example

## Prerequisites

- g++ or clang++ (C++17+)
- cpp-httplib (header-only, included)
- nlohmann/json (header-only, included)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make
```

If the header-only libraries are not already present, download them:

```bash
wget -O httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
wget -O json.hpp https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp
```

## Build

```bash
make
```

## Run

```bash
./logging_api
```

The application starts a cpp-httplib API server on port 9189.

## Test the Endpoints

Health check:

```bash
curl http://localhost:9189/api/health
```

Login:

```bash
curl -X POST http://localhost:9189/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

List users (use token from login response):

```bash
curl http://localhost:9189/api/admin/users \
  -H "Authorization: Bearer <token>"
```

Create a transaction:

```bash
curl -X POST http://localhost:9189/api/transactions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"amount": 500.00, "recipient": "vendor@example.com", "description": "Payment"}'
```

Export data:

```bash
curl -X POST http://localhost:9189/api/export/data \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "users"}'
```

Toggle MFA:

```bash
curl -X PUT http://localhost:9189/api/settings/mfa \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"enabled": false}'
```
