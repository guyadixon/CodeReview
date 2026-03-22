# Integrity Failures - Go Example

## Prerequisites

- Go 1.21+

Install Go on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official site:

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
go build -o integrity-service main.go
```

## Run

```bash
./integrity-service
```

The application starts a Gin API server on port 8008.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:8008/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create a pipeline:

```bash
curl -X POST http://localhost:8008/api/pipelines \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name": "build-pipeline", "stages": ["compile", "test", "deploy"]}'
```

Import a pipeline (JSON format):

```bash
curl -X POST http://localhost:8008/api/pipelines/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"payload": "eyJuYW1lIjoiZGVtbyIsInN0YWdlcyI6W119", "format": "json"}'
```

Export a pipeline:

```bash
curl -X POST http://localhost:8008/api/pipelines/export \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"pipeline_id": 1, "format": "json"}'
```

Store an object:

```bash
curl -X POST http://localhost:8008/api/objects/store \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"key": "config-v1", "data": {"setting": "enabled"}}'
```

Retrieve an object:

```bash
curl http://localhost:8008/api/objects/config-v1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Run a script (admin/engineer only):

```bash
curl -X POST http://localhost:8008/api/scripts/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"script": "echo hello", "args": ""}'
```

List plugins:

```bash
curl http://localhost:8008/api/plugins \
  -H "Authorization: Bearer YOUR_TOKEN"
```

List users:

```bash
curl http://localhost:8008/api/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```
