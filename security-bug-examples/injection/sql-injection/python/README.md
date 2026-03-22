# SQL Injection - Python Example

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

The application starts a Flask API server on port 5000.

## Test the Endpoints

Create a product:

```bash
curl -X POST http://localhost:5000/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Laptop", "category": "electronics", "price": 999.99, "stock": 10}'
```

Search products:

```bash
curl "http://localhost:5000/api/products/search?q=Laptop"
```

List products with sorting:

```bash
curl "http://localhost:5000/api/products?sort=price&order=DESC"
```

List products by category:

```bash
curl "http://localhost:5000/api/products?category=electronics"
```

Create a customer:

```bash
curl -X POST http://localhost:5000/api/customers \
  -H "Content-Type: application/json" \
  -d '{"username": "jdoe", "email": "jdoe@example.com"}'
```

Create an order:

```bash
curl -X POST http://localhost:5000/api/orders \
  -H "Content-Type: application/json" \
  -d '{"customer_id": 1, "product_id": 1, "quantity": 2}'
```

List orders:

```bash
curl "http://localhost:5000/api/orders?customer_id=1&status=pending"
```
