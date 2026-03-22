# Auth Failures - C++ Example

## Prerequisites

- g++ or clang++ (C++17+)
- cpp-httplib (header-only, included via system headers or local copy)
- nlohmann/json (header-only)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make nlohmann-json3-dev
```

For cpp-httplib, download the header:

```bash
sudo mkdir -p /usr/include/httplib
sudo wget -O /usr/include/httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
```

## Build

```bash
make
```

## Run

```bash
./auth-server
```

The application starts a cpp-httplib API server on port 8096.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8096/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin_vault1"}'
```

Verify a token:

```bash
curl -X POST http://localhost:8096/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"YOUR_TOKEN_HERE"}'
```

Request password reset:

```bash
curl -X POST http://localhost:8096/api/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@logvault.io"}'
```

Reset password:

```bash
curl -X POST http://localhost:8096/api/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token":"RESET_TOKEN","newPassword":"newpass123"}'
```

Get current user:

```bash
curl http://localhost:8096/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

List users:

```bash
curl http://localhost:8096/api/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Deactivate a user:

```bash
curl -X POST http://localhost:8096/api/users/1/deactivate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
