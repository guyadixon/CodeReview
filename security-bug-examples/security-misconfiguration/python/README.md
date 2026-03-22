# Security Misconfiguration - Python Example

## Prerequisites

- Python 3.10+
- pip (Python package manager)

Install Python on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv
```

## Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
source venv/bin/activate
python3 app.py
```

The application starts a Flask API server on port 5008.

## Test the Endpoints

List products:

```bash
curl http://localhost:5008/api/products
```

Get a single product:

```bash
curl http://localhost:5008/api/products/1
```

Create a product:

```bash
curl -X POST http://localhost:5008/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Widget", "sku": "TW-001", "price": 19.99, "stock": 50}'
```

Import products via XML:

```bash
curl -X POST http://localhost:5008/api/products/import \
  -H "Content-Type: application/xml" \
  -d '<products><product><name>Imported Item</name><sku>II-100</sku><price>9.99</price><stock>25</stock></product></products>'
```

Import orders via XML:

```bash
curl -X POST http://localhost:5008/api/orders/import \
  -H "Content-Type: application/xml" \
  -d '<orders><order><customer>Alice</customer><product_sku>WP-100</product_sku><quantity>2</quantity><notes>Rush</notes></order></orders>'
```

Get settings:

```bash
curl http://localhost:5008/api/settings
```

Update settings:

```bash
curl -X PUT http://localhost:5008/api/settings \
  -H "Content-Type: application/json" \
  -d '{"maintenance_mode": true}'
```

Admin diagnostics:

```bash
curl http://localhost:5008/api/admin/diagnostics \
  -H "X-Admin-Token: super-admin-token-2024"
```

Admin environment:

```bash
curl http://localhost:5008/api/admin/env \
  -H "X-Admin-Token: super-admin-token-2024"
```

Health check:

```bash
curl http://localhost:5008/api/health
```
