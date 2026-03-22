# Security Misconfiguration - Rust Example

## Prerequisites

- Rust 1.70+
- Cargo (included with Rust)

Install Rust on Ubuntu/Debian:

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
cargo run
```

The application starts an Actix-web API server on port 8098.

## Test the Endpoints

List products:

```bash
curl http://localhost:8098/api/products
```

Get a single product:

```bash
curl http://localhost:8098/api/products/1
```

Create a product:

```bash
curl -X POST http://localhost:8098/api/products \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Widget", "sku": "TW-001", "price": 19.99, "stock": 50}'
```

Import products via XML:

```bash
curl -X POST http://localhost:8098/api/products/import \
  -H "Content-Type: application/xml" \
  -d '<products><product><name>Imported Item</name><sku>II-100</sku><price>9.99</price><stock>25</stock></product></products>'
```

Import orders via XML:

```bash
curl -X POST http://localhost:8098/api/orders/import \
  -H "Content-Type: application/xml" \
  -d '<orders><order><customer>Alice</customer><product_sku>WP-100</product_sku><quantity>2</quantity><notes>Rush</notes></order></orders>'
```

Get settings:

```bash
curl http://localhost:8098/api/settings
```

Update settings:

```bash
curl -X PUT http://localhost:8098/api/settings \
  -H "Content-Type: application/json" \
  -d '{"maintenance_mode": true}'
```

Admin diagnostics:

```bash
curl http://localhost:8098/api/admin/diagnostics \
  -H "X-Admin-Token: super-admin-token-2024"
```

Admin environment:

```bash
curl http://localhost:8098/api/admin/env \
  -H "X-Admin-Token: super-admin-token-2024"
```

Health check:

```bash
curl http://localhost:8098/api/health
```
