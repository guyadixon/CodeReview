# Security Misconfiguration - C Example

## Prerequisites

- GCC or Clang (C11+)
- libmicrohttpd development headers
- libxml2 development headers

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y gcc make libmicrohttpd-dev libxml2-dev
```

## Build

```bash
make
```

## Run

```bash
./config_api
```

The application starts a libmicrohttpd API server on port 9088. Press Enter to stop the server.

## Test the Endpoints

List products:

```bash
curl http://localhost:9088/api/products
```

Create a product:

```bash
curl -X POST http://localhost:9088/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Widget", "sku": "TW-001", "price": 19.99, "stock": 50}'
```

Import products via XML:

```bash
curl -X POST http://localhost:9088/api/products/import \
  -H "Content-Type: application/xml" \
  -d '<products><product><name>Imported Item</name><sku>II-100</sku><price>9.99</price><stock>25</stock></product></products>'
```

Get settings:

```bash
curl http://localhost:9088/api/settings
```

Admin diagnostics:

```bash
curl http://localhost:9088/api/admin/diagnostics \
  -H "X-Admin-Token: super-admin-token-2024"
```

Health check:

```bash
curl http://localhost:9088/api/health
```
