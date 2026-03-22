# Broken Access Control - C Example

## Prerequisites

- gcc or clang (C11+)
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
./clinic-api
```

The application starts a libmicrohttpd API server on port 8090. Press Enter to stop the server.

## Test the Endpoints

Get a user profile:

```bash
curl http://localhost:8090/api/users/1
```

Get a medical record:

```bash
curl http://localhost:8090/api/records/501 \
  -H "Authorization: Bearer tok_jones"
```

Update a medical record:

```bash
curl -X PUT http://localhost:8090/api/records/501 \
  -H "Authorization: Bearer tok_jones" \
  -H "Content-Type: application/json" \
  -d '{"diagnosis": "Hypertension Stage 1", "status": "active"}'
```

List all users (admin):

```bash
curl http://localhost:8090/api/admin/users \
  -H "Authorization: Bearer tok_smith" \
  -H "X-User-Role: admin"
```

Update a user's role:

```bash
curl -X PUT http://localhost:8090/api/users/3/role \
  -H "Authorization: Bearer tok_smith" \
  -H "Content-Type: application/json" \
  -d '{"role": "doctor"}'
```

Debug configuration:

```bash
curl http://localhost:8090/api/debug/config
```
