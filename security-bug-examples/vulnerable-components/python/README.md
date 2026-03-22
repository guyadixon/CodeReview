# Vulnerable Components - Python Example

## Prerequisites

- Python 3.10+
- pip

Install on Ubuntu/Debian:

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
python3 app.py
```

The application starts a Flask API server on port 5010.

## Test the Endpoints

List products:

```bash
curl http://localhost:5010/api/products
```

Get a product:

```bash
curl http://localhost:5010/api/products/1
```

Create an order:

```bash
curl -X POST http://localhost:5010/api/orders \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": 2}], "email": "user@example.com"}'
```

Import inventory (JSON):

```bash
curl -X POST http://localhost:5010/api/inventory/import \
  -H "Content-Type: application/json" \
  -d '{"format": "json", "payload": {"products": [{"id": 1, "stock": 200}]}}'
```

Generate product label:

```bash
curl "http://localhost:5010/api/products/1/label"
```

Warehouse sync:

```bash
curl -X POST http://localhost:5010/api/warehouse/sync \
  -H "Content-Type: application/json" \
  -d '{}'
```

Health check:

```bash
curl http://localhost:5010/api/health
```
