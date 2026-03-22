# Broken Access Control - Go Example

## Prerequisites

- Go 1.21+

Install Go on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official tarball:

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
go build -o helpdesk-api main.go
```

## Run

```bash
./helpdesk-api
```

The application starts a Gin API server on port 8088.

## Test the Endpoints

Get a user profile:

```bash
curl http://localhost:8088/api/users/1
```

Get a ticket:

```bash
curl http://localhost:8088/api/tickets/301 \
  -H "Authorization: Bearer tok_bob"
```

Update a ticket:

```bash
curl -X PUT http://localhost:8088/api/tickets/302 \
  -H "Authorization: Bearer tok_bob" \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved"}'
```

Delete a ticket:

```bash
curl -X DELETE http://localhost:8088/api/tickets/303 \
  -H "Authorization: Bearer tok_bob"
```

List all users (admin):

```bash
curl http://localhost:8088/api/admin/users \
  -H "Authorization: Bearer tok_alice" \
  -H "X-User-Role: admin"
```

Update a user's role:

```bash
curl -X PUT http://localhost:8088/api/users/3/role \
  -H "Authorization: Bearer tok_alice" \
  -H "Content-Type: application/json" \
  -d '{"role": "agent"}'
```

Debug configuration:

```bash
curl http://localhost:8088/api/debug/config
```
