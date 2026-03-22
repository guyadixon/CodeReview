# Broken Access Control - C++ Example

## Prerequisites

- g++ or clang++ (C++17+)
- cpp-httplib (header-only)
- nlohmann/json (header-only)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make nlohmann-json3-dev
```

Install cpp-httplib header:

```bash
sudo mkdir -p /usr/local/include
sudo wget -O /usr/local/include/httplib.h \
  https://raw.githubusercontent.com/yhirose/cpp-httplib/v0.14.1/httplib.h
```

## Build

```bash
make
```

## Run

```bash
./inventory-api
```

The application starts a cpp-httplib API server on port 8091.

## Test the Endpoints

Get a user profile:

```bash
curl http://localhost:8091/api/users/1
```

Get an asset:

```bash
curl http://localhost:8091/api/assets/601 \
  -H "Authorization: Bearer tok_alice"
```

Update an asset:

```bash
curl -X PUT http://localhost:8091/api/assets/602 \
  -H "Authorization: Bearer tok_bob" \
  -H "Content-Type: application/json" \
  -d '{"location": "Warehouse C", "status": "maintenance"}'
```

List all users (admin):

```bash
curl http://localhost:8091/api/admin/users \
  -H "Authorization: Bearer tok_alice" \
  -H "X-User-Role: admin"
```

Update a user's role:

```bash
curl -X PUT http://localhost:8091/api/users/3/role \
  -H "Authorization: Bearer tok_alice" \
  -H "Content-Type: application/json" \
  -d '{"role": "manager"}'
```

Debug configuration:

```bash
curl http://localhost:8091/api/debug/config
```
