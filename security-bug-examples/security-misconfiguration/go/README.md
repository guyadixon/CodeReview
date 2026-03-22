# Security Misconfiguration - Go Example

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
go build -o config-api main.go
```

## Run

```bash
go run main.go
```

The application starts a Gin API server on port 8088.

## Test the Endpoints

List products:

```bash
curl http://localhost:8088/api/products
```

Get a single product:

```bash
curl http://localhost:8088/api/products/1
```

Create a product:

```bash
curl -X POST http://localhost:8088/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Widget", "sku": "TW-001", "price": 19.99, "stock": 50}'
```

Import products via XML:

```bash
curl -X POST http://localhost:8088/api/products/import \
  -H "Content-Type: application/xml" \
  -d '<products><product><name>Imported Item</name><sku>II-100</sku><price>9.99</price><stock>25</stock></product></products>'
```

Import orders via XML:

```bash
curl -X POST http://localhost:8088/api/orders/import \
  -H "Content-Type: application/xml" \
  -d '<orders><order><customer>Alice</customer><product_sku>WP-100</product_sku><quantity>2</quantity><notes>Rush</notes></order></orders>'
```

Get settings:

```bash
curl http://localhost:8088/api/settings
```

Update settings:

```bash
curl -X PUT http://localhost:8088/api/settings \
  -H "Content-Type: application/json" \
  -d '{"maintenance_mode": true}'
```

Admin diagnostics:

```bash
curl http://localhost:8088/api/admin/diagnostics \
  -H "X-Admin-Token: super-admin-token-2024"
```

Admin environment:

```bash
curl http://localhost:8088/api/admin/env \
  -H "X-Admin-Token: super-admin-token-2024"
```

Health check:

```bash
curl http://localhost:8088/api/health
```
