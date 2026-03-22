# Vulnerable Components - Go Example

## Prerequisites

- Go 1.21+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official Go website for the latest version.

## Install Dependencies

```bash
go mod download
```

## Build

```bash
go build -o inventory-server main.go
```

## Run

```bash
./inventory-server
```

The application starts a Gin API server on port 8010.

## Test the Endpoints

List products:

```bash
curl http://localhost:8010/api/products
```

Get a product:

```bash
curl http://localhost:8010/api/products/1
```

Filter by category:

```bash
curl "http://localhost:8010/api/products?category=electronics"
```

Create an order:

```bash
curl -X POST http://localhost:8010/api/orders \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": 2}], "email": "user@example.com"}'
```

Import inventory (YAML):

```bash
curl -X POST http://localhost:8010/api/inventory/import \
  -H "Content-Type: application/json" \
  -d '{"format": "yaml", "payload": "products:\n  - id: 1\n    stock: 300"}'
```

Sync warehouse:

```bash
curl -X POST http://localhost:8010/api/warehouse/sync \
  -H "Content-Type: application/json" \
  -d '{}'
```

Health check:

```bash
curl http://localhost:8010/api/health
```
