# Cross-Site Scripting (XSS) - Rust Example

## Prerequisites

- Rust 1.70+
- Cargo (included with Rust)

Install Rust on Ubuntu/Debian:

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

The application starts an Actix-web server on port 8086.

## Test the Application

Browse the forum home page:

```bash
curl http://localhost:8086/
```

View a thread:

```bash
curl http://localhost:8086/thread/0
```

Create a new thread:

```bash
curl -X POST http://localhost:8086/new \
  -d "author=testuser&title=My+Thread&content=Hello+world"
```

Add a reply:

```bash
curl -X POST http://localhost:8086/thread/0/reply \
  -d "author=commenter&body=Nice+thread"
```

Search threads:

```bash
curl "http://localhost:8086/search?q=welcome"
```

View error page:

```bash
curl "http://localhost:8086/error?msg=Something+went+wrong"
```

Save a profile:

```bash
curl -X POST http://localhost:8086/profile \
  -d "username=testuser&display_name=Test+User&bio=Hello&website=http://example.com"
```

API endpoint with JSONP:

```bash
curl "http://localhost:8086/api/posts?callback=myCallback"
```
