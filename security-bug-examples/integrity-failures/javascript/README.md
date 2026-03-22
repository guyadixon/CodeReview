# Integrity Failures - JavaScript Example

## Prerequisites

- Node.js 18+
- npm (Node package manager)

Install Node.js on Ubuntu/Debian:

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

## Install Dependencies

```bash
npm install
```

## Run

```bash
node app.js
```

The application starts an Express API server on port 3008.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:3008/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create a job:

```bash
curl -X POST http://localhost:3008/api/jobs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name": "build-job", "steps": [{"action": "compile"}, {"action": "test"}]}'
```

Import a job:

```bash
curl -X POST http://localhost:3008/api/jobs/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"payload": "{\"name\": \"imported-job\", \"steps\": []}"}'
```

Export a job:

```bash
curl -X POST http://localhost:3008/api/jobs/export \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"jobId": 1}'
```

Create a template:

```bash
curl -X POST http://localhost:3008/api/templates \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name": "greeting", "body": "Hello ${variables.name}!"}'
```

Render a template:

```bash
curl -X POST http://localhost:3008/api/templates/1/render \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"variables": {"name": "World"}}'
```

Store data:

```bash
curl -X POST http://localhost:3008/api/data/store \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"key": "config-v1", "value": {"setting": "enabled"}}'
```

Retrieve data:

```bash
curl http://localhost:3008/api/data/config-v1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

List users:

```bash
curl http://localhost:3008/api/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```
