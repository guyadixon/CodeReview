# Integrity Failures - Python Example

## Prerequisites

- Python 3.10+
- pip (Python package manager)

Install Python on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv
```

## Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
source venv/bin/activate
python3 app.py
```

The application starts a Flask API server on port 5008.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:5008/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create a workflow:

```bash
curl -X POST http://localhost:5008/api/workflows \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name": "build-pipeline", "steps": [{"action": "compile"}, {"action": "test"}]}'
```

Import a workflow (JSON format):

```bash
curl -X POST http://localhost:5008/api/workflows/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"payload": "eyJuYW1lIjogInRlc3Qtd29ya2Zsb3ciLCAic3RlcHMiOiBbXX0=", "format": "json"}'
```

Export a workflow:

```bash
curl -X POST http://localhost:5008/api/workflows/export \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"workflow_id": 1, "format": "json"}'
```

Store a cache entry:

```bash
curl -X POST http://localhost:5008/api/cache/store \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"key": "config-v1", "value": {"setting": "enabled"}}'
```

Retrieve a cache entry:

```bash
curl http://localhost:5008/api/cache/config-v1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Load configuration:

```bash
curl -X POST http://localhost:5008/api/config/load \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"config_data": "settings:\n  debug: false\npipeline_defaults:\n  timeout: 300"}'
```

Install a plugin:

```bash
curl -X POST http://localhost:5008/api/plugins/install \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"module_name": "json", "source_url": null}'
```

List users:

```bash
curl http://localhost:5008/api/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```
