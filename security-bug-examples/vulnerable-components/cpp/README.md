# Vulnerable Components - C++ Example

## Prerequisites

- g++ or clang++ (C++17+)
- pthread library
- cpp-httplib header (httplib.h)
- nlohmann/json header (json.hpp)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make
```

Download header-only dependencies:

```bash
wget -O httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
wget -O json.hpp https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp
```

## Build

```bash
make
```

## Run

```bash
./inventory-server
```

The application starts a cpp-httplib API server on port 9110.

## Test the Endpoints

List products:

```bash
curl http://localhost:9110/api/products
```

Get a product:

```bash
curl http://localhost:9110/api/products/1
```

Filter by category:

```bash
curl "http://localhost:9110/api/products?category=electronics"
```

Create an order:

```bash
curl -X POST http://localhost:9110/api/orders \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": 2}], "email": "user@example.com"}'
```

Import inventory:

```bash
curl -X POST http://localhost:9110/api/inventory/import \
  -H "Content-Type: application/json" \
  -d '{"payload": {"products": [{"id": 1, "stock": 200}]}}'
```

Generate product label:

```bash
curl http://localhost:9110/api/products/1/label
```

Warehouse config:

```bash
curl http://localhost:9110/api/config/warehouse
```

Health check:

```bash
curl http://localhost:9110/api/health
```
