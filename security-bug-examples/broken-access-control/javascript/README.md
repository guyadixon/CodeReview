# Broken Access Control - JavaScript Example

## Prerequisites

- Node.js 18+
- npm (Node package manager)

Install Node.js on Ubuntu/Debian:

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

## Install Dependencies

```bash
npm install
```

## Run

```bash
node app.js
```

The application starts an Express API server on port 3003.

## Test the Endpoints

Get a user profile:

```bash
curl http://localhost:3003/api/users/1
```

Get an invoice:

```bash
curl http://localhost:3003/api/invoices/1001 \
  -H "Authorization: Bearer sess_alice"
```

Update an invoice:

```bash
curl -X PUT http://localhost:3003/api/invoices/1002 \
  -H "Authorization: Bearer sess_bob" \
  -H "Content-Type: application/json" \
  -d '{"status": "approved"}'
```

List all users (admin):

```bash
curl http://localhost:3003/api/admin/users \
  -H "Authorization: Bearer sess_alice" \
  -H "x-user-role: admin"
```

Update a user's role:

```bash
curl -X PUT http://localhost:3003/api/users/3/role \
  -H "Authorization: Bearer sess_alice" \
  -H "Content-Type: application/json" \
  -d '{"role": "manager"}'
```

Debug environment:

```bash
curl http://localhost:3003/api/debug/env
```
