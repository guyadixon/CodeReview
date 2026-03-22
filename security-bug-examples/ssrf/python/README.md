# SSRF - Python Example

## Prerequisites

- Python 3.10+
- pip

Install on Ubuntu/Debian:

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
python3 app.py
```

The application starts a Flask API server on port 5010.

## Test the Endpoints

Health check:

```bash
curl http://localhost:5010/api/health
```

Login:

```bash
curl -X POST http://localhost:5010/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

Fetch a URL (use token from login response):

```bash
curl -X POST http://localhost:5010/api/fetch-url \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"url": "https://httpbin.org/get"}'
```

Preview a link:

```bash
curl "http://localhost:5010/api/preview?target=https://example.com" \
  -H "Authorization: Bearer <token>"
```

Register a webhook:

```bash
curl -X POST http://localhost:5010/api/webhooks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"callback_url": "https://httpbin.org/post", "event_type": "deploy"}'
```

Test a webhook:

```bash
curl -X POST http://localhost:5010/api/webhooks/<webhook_id>/test \
  -H "Authorization: Bearer <token>"
```

Import configuration:

```bash
curl -X POST http://localhost:5010/api/integrations/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"config_url": "https://httpbin.org/json"}'
```

Proxy a service request:

```bash
curl "http://localhost:5010/api/proxy?service=analytics&path=/status" \
  -H "Authorization: Bearer <token>"
```
