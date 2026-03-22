# Command Injection - Rust Example

## Prerequisites

- Rust 1.70+
- Cargo (included with Rust)

Install on Ubuntu/Debian:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Install Dependencies and Build

```bash
cargo build --release
```

## Run

```bash
cargo run --release
```

Or run the compiled binary:

```bash
./target/release/sysadmin-api
```

The application starts an Actix-web API server on port 8083.

## Test the Endpoints

Ping a host:

```bash
curl "http://localhost:8083/api/ping?host=127.0.0.1"
```

DNS lookup:

```bash
curl "http://localhost:8083/api/dns/lookup?domain=example.com&type=A"
```

Search logs:

```bash
curl "http://localhost:8083/api/logs/search?keyword=error&file=syslog&lines=50"
```

List files:

```bash
curl "http://localhost:8083/api/files/list?path=/tmp"
```

Create an archive:

```bash
curl -X POST http://localhost:8083/api/files/archive \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/uploads", "name": "backup"}'
```

Check port connectivity:

```bash
curl -X POST http://localhost:8083/api/network/check \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1", "port": 80}'
```

System information:

```bash
curl "http://localhost:8083/api/system/info"
```

Check certificate:

```bash
curl -X POST http://localhost:8083/api/certs/check \
  -H "Content-Type: application/json" \
  -d '{"hostname": "example.com", "port": 443}'
```
