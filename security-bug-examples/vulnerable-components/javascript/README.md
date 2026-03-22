# Vulnerable Components - JavaScript Example

## Prerequisites

- Node.js 18+
- npm

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm
```

Or use nvm for version management:

```bash
nvm install 18
nvm use 18
```

## Install Dependencies

```bash
npm install
```

## Run

```bash
node app.js
```

The application starts an Express API server on port 3010.

## Test the Endpoints

List products:

```bash
curl http://localhost:3010/api/products
```

Get a product:

```bash
curl http://localhost:3010/api/products/1
```

Create an order:

```bash
curl -X POST http://localhost:3010/api/orders \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": 2}], "email": "user@example.com"}'
```

Import inventory:

```bash
curl -X POST http://localhost:3010/api/inventory/import \
  -H "Content-Type: application/json" \
  -d '{"payload": {"products": [{"id": 1, "stock": 200}]}}'
```

Generate product label:

```bash
curl "http://localhost:3010/api/products/1/label"
```

Get product description (markdown):

```bash
curl "http://localhost:3010/api/products/1/description"
```

Warehouse sync:

```bash
curl -X POST http://localhost:3010/api/warehouse/sync \
  -H "Content-Type: application/json" \
  -d '{}'
```

Health check:

```bash
curl http://localhost:3010/api/health
```
