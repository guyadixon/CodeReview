# Security Misconfiguration - JavaScript Example

## Prerequisites

- Node.js 18+
- npm (Node.js package manager)

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

The application starts an Express API server on port 3008.

## Test the Endpoints

List products:

```bash
curl http://localhost:3008/api/products
```

Get a single product:

```bash
curl http://localhost:3008/api/products/1
```

Create a product:

```bash
curl -X POST http://localhost:3008/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Widget", "sku": "TW-001", "price": 19.99, "stock": 50}'
```

Import products via XML:

```bash
curl -X POST http://localhost:3008/api/products/import \
  -H "Content-Type: application/xml" \
  -d '<products><product><name>Imported Item</name><sku>II-100</sku><price>9.99</price><stock>25</stock></product></products>'
```

Import orders via XML:

```bash
curl -X POST http://localhost:3008/api/orders/import \
  -H "Content-Type: application/xml" \
  -d '<orders><order><customer>Alice</customer><product_sku>WP-100</product_sku><quantity>2</quantity><notes>Rush</notes></order></orders>'
```

Get settings:

```bash
curl http://localhost:3008/api/settings
```

Update settings:

```bash
curl -X PUT http://localhost:3008/api/settings \
  -H "Content-Type: application/json" \
  -d '{"maintenanceMode": true}'
```

Admin diagnostics:

```bash
curl http://localhost:3008/api/admin/diagnostics \
  -H "X-Admin-Token: super-admin-token-2024"
```

Admin environment:

```bash
curl http://localhost:3008/api/admin/env \
  -H "X-Admin-Token: super-admin-token-2024"
```

Health check:

```bash
curl http://localhost:3008/api/health
```
