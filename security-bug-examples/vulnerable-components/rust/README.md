# Vulnerable Components - Rust Example

## Prerequisites

- Rust 1.70+ (via rustup)

Install on Ubuntu/Debian:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run --release
```

The application starts an Actix-web API server on port 8110.

## Test the Endpoints

List products:

```bash
curl http://localhost:8110/api/products
```

Get a product:

```bash
curl http://localhost:8110/api/products/1
```

Filter by category:

```bash
curl "http://localhost:8110/api/products?category=electronics"
```

Create an order:

```bash
curl -X POST http://localhost:8110/api/orders \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": 2}], "email": "user@example.com"}'
```

Import inventory:

```bash
curl -X POST http://localhost:8110/api/inventory/import \
  -H "Content-Type: application/json" \
  -d '{"payload": {"products": [{"id": 1, "stock": 200}]}}'
```

Generate product label:

```bash
curl http://localhost:8110/api/products/1/label
```

Health check:

```bash
curl http://localhost:8110/api/health
```
