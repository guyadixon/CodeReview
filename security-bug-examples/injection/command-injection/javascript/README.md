# Command Injection - JavaScript Example

## Prerequisites

- Node.js 18+
- npm (included with Node.js)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm
```

Or install via nvm for the latest version:

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
```

## Install Dependencies

```bash
npm install
```

## Run

```bash
node app.js
```

The application starts an Express.js API server on port 3001.

## Test the Endpoints

Ping a host:

```bash
curl "http://localhost:3001/api/ping?host=127.0.0.1"
```

DNS lookup:

```bash
curl "http://localhost:3001/api/dns/lookup?domain=example.com&type=A"
```

Search logs:

```bash
curl "http://localhost:3001/api/logs/search?keyword=error&file=syslog&context=2"
```

List files:

```bash
curl "http://localhost:3001/api/files/list?path=/tmp"
```

Create an archive:

```bash
curl -X POST http://localhost:3001/api/files/archive \
  -H "Content-Type: application/json" \
  -d '{"filePath": "/tmp/uploads", "name": "backup"}'
```

System information:

```bash
curl "http://localhost:3001/api/system/info"
```

Check port connectivity:

```bash
curl -X POST http://localhost:3001/api/network/check \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1", "port": 80}'
```

Check certificate:

```bash
curl -X POST http://localhost:3001/api/certs/check \
  -H "Content-Type: application/json" \
  -d '{"hostname": "example.com", "port": 443}'
```
