# Command Injection - Go Example

## Prerequisites

- Go 1.21+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official Go website for the latest version.

## Install Dependencies

```bash
go mod download
```

## Build

```bash
go build -o sysadmin-api main.go
```

## Run

```bash
go run main.go
```

Or run the compiled binary:

```bash
./sysadmin-api
```

The application starts a Gin API server on port 8082.

## Test the Endpoints

Ping a host:

```bash
curl "http://localhost:8082/api/ping?host=127.0.0.1"
```

DNS lookup:

```bash
curl "http://localhost:8082/api/dns/lookup?domain=example.com&type=A"
```

Search logs:

```bash
curl "http://localhost:8082/api/logs/search?keyword=error&file=syslog&lines=50"
```

List files:

```bash
curl "http://localhost:8082/api/files/list?path=/tmp"
```

Create an archive:

```bash
curl -X POST http://localhost:8082/api/files/archive \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/uploads", "name": "backup"}'
```

Check port connectivity:

```bash
curl -X POST http://localhost:8082/api/network/check \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1", "port": 80}'
```

System information:

```bash
curl "http://localhost:8082/api/system/info"
```

WHOIS lookup:

```bash
curl "http://localhost:8082/api/whois?domain=example.com"
```
