# Security Misconfiguration - C++ Example

## Prerequisites

- G++ or Clang++ (C++17+)
- libxml2 development headers

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make libxml2-dev
```

This example uses header-only libraries (cpp-httplib and nlohmann/json) which should be placed in the project directory or installed system-wide.

## Build

```bash
make
```

## Run

```bash
./config_api
```

The application starts a cpp-httplib API server on port 9188.

## Test the Endpoints

List products:

```bash
curl http://localhost:9188/api/products
```

Get a single product:

```bash
curl http://localhost:9188/api/products/1
```

Create a product:

```bash
curl -X POST http://localhost:9188/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Widget", "sku": "TW-001", "price": 19.99, "stock": 50}'
```

Import products via XML:

```bash
curl -X POST http://localhost:9188/api/products/import \
  -H "Content-Type: application/xml" \
  -d '<products><product><name>Imported Item</name><sku>II-100</sku><price>9.99</price><stock>25</stock></product></products>'
```

Get settings:

```bash
curl http://localhost:9188/api/settings
```

Update settings:

```bash
curl -X PUT http://localhost:9188/api/settings \
  -H "Content-Type: application/json" \
  -d '{"log_level": "INFO"}'
```

Admin diagnostics:

```bash
curl http://localhost:9188/api/admin/diagnostics \
  -H "X-Admin-Token: super-admin-token-2024"
```

Health check:

```bash
curl http://localhost:9188/api/health
```
