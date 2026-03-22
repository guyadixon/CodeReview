# Vulnerable Components - C Example

## Prerequisites

- GCC or Clang (C11+)
- libmicrohttpd development headers
- libcurl development headers
- Jansson development headers

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y gcc make libmicrohttpd-dev libcurl4-openssl-dev libjansson-dev
```

## Build

```bash
make
```

## Run

```bash
./inventory-server
```

The application starts a libmicrohttpd API server on port 9010. Press Enter to stop the server.

## Test the Endpoints

List products:

```bash
curl http://localhost:9010/api/products
```

Get a product:

```bash
curl http://localhost:9010/api/products/1
```

Filter by category:

```bash
curl "http://localhost:9010/api/products?category=electronics"
```

Create an order:

```bash
curl -X POST http://localhost:9010/api/orders \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": 2}], "email": "user@example.com"}'
```

Get an order:

```bash
curl http://localhost:9010/api/orders/1001
```

Warehouse config:

```bash
curl http://localhost:9010/api/config/warehouse
```

Health check:

```bash
curl http://localhost:9010/api/health
```
