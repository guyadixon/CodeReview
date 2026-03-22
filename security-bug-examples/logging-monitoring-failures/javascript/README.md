# Logging/Monitoring Failures - JavaScript Example

## Prerequisites

- Node.js 18+
- npm

Install on Ubuntu/Debian:

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

The application starts an Express.js API server on port 3009.

## Test the Endpoints

Health check:

```bash
curl http://localhost:3009/api/health
```

Login:

```bash
curl -X POST http://localhost:3009/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

List users (use token from login response):

```bash
curl http://localhost:3009/api/admin/users \
  -H "Authorization: Bearer <token>"
```

Create a transaction:

```bash
curl -X POST http://localhost:3009/api/transactions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"amount": 500.00, "recipient": "vendor@example.com", "description": "Payment"}'
```

Bulk transfer:

```bash
curl -X POST http://localhost:3009/api/transactions/bulk \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"transfers": [{"amount": 100, "recipient": "a@example.com"}, {"amount": 200, "recipient": "b@example.com"}]}'
```

Export data:

```bash
curl -X POST http://localhost:3009/api/export/data \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "users"}'
```
