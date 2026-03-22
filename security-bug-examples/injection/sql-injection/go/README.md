# SQL Injection - Go Example

## Prerequisites

- Go 1.21+
- GCC (required for go-sqlite3 CGO compilation)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go gcc sqlite3
```

If your distribution provides an older Go version, install from the official site:

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
CGO_ENABLED=1 go build -o server main.go
```

## Run

```bash
./server
```

The application starts a Gin API server on port 8080.

## Test the Endpoints

Create a product:

```bash
curl -X POST http://localhost:8080/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Laptop", "category": "electronics", "price": 999.99, "stock": 10}'
```

Search products:

```bash
curl "http://localhost:8080/api/products/search?q=Laptop"
```

List products with sorting:

```bash
curl "http://localhost:8080/api/products?sort=price&order=DESC"
```

List products by category:

```bash
curl "http://localhost:8080/api/products?category=electronics"
```

Get a customer:

```bash
curl "http://localhost:8080/api/customers/1"
```

List orders with filters:

```bash
curl "http://localhost:8080/api/orders?customer_id=1&status=pending"
```

List orders with tag filter:

```bash
curl "http://localhost:8080/api/orders?customer_id=1&tags=laptop,phone"
```
