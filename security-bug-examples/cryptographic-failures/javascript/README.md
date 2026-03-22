# Cryptographic Failures - JavaScript Example

## Prerequisites

- Node.js 18+
- npm

Install Node.js on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm
```

Or install via nvm:

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
nvm use 18
```

## Install Dependencies

```bash
npm install
```

## Run

```bash
node app.js
```

The application starts an Express.js API server on port 3005.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:3005/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create an encrypted record:

```bash
curl -X POST http://localhost:3005/api/records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"content": "sensitive data here"}'
```

Retrieve a record:

```bash
curl http://localhost:3005/api/records/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Verify record integrity:

```bash
curl -X POST http://localhost:3005/api/records/1/verify \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Generate an API token:

```bash
curl -X POST http://localhost:3005/api/tokens/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"label": "my-token"}'
```

Hash data:

```bash
curl -X POST http://localhost:3005/api/hash \
  -H "Content-Type: application/json" \
  -d '{"value": "test", "algorithm": "md5"}'
```

Encrypt data:

```bash
curl -X POST http://localhost:3005/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "hello world"}'
```
