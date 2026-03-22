# SQL Injection - JavaScript Example

## Prerequisites

- Node.js 18+
- npm (included with Node.js)
- Build tools for native modules (better-sqlite3 requires compilation)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm build-essential python3
```

If your distribution provides an older Node.js version, install via NodeSource:

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

The application starts an Express.js API server on port 3000.

## Test the Endpoints

Create a product:

```bash
curl -X POST http://localhost:3000/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Laptop", "category": "electronics", "price": 999.99, "stock": 10}'
```

Search products:

```bash
curl "http://localhost:3000/api/products/search?q=Laptop"
```

List products with sorting:

```bash
curl "http://localhost:3000/api/products?sort=price&order=DESC"
```

List products by category:

```bash
curl "http://localhost:3000/api/products?category=electronics"
```

Create a customer:

```bash
curl -X POST http://localhost:3000/api/customers \
  -H "Content-Type: application/json" \
  -d '{"username": "jdoe", "email": "jdoe@example.com"}'
```

Create an order:

```bash
curl -X POST http://localhost:3000/api/orders \
  -H "Content-Type: application/json" \
  -d '{"customer_id": 1, "product_id": 1, "quantity": 2}'
```

List orders:

```bash
curl "http://localhost:3000/api/orders?customer_id=1&status=pending"
```

Product reports with custom fields:

```bash
curl "http://localhost:3000/api/reports/products?fields=name,price,stock&category=electronics"
```
