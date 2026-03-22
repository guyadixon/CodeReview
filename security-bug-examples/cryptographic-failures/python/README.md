# Cryptographic Failures - Python Example

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

The application starts a Flask API server on port 5005.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:5005/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Create an encrypted record:

```bash
curl -X POST http://localhost:5005/api/records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"content": "sensitive data here"}'
```

Retrieve a record:

```bash
curl http://localhost:5005/api/records/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Verify record integrity:

```bash
curl -X POST http://localhost:5005/api/records/1/verify \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Generate an API token:

```bash
curl -X POST http://localhost:5005/api/tokens/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"label": "my-token"}'
```

Hash data:

```bash
curl -X POST http://localhost:5005/api/hash \
  -H "Content-Type: application/json" \
  -d '{"value": "test", "algorithm": "md5"}'
```

Encrypt data:

```bash
curl -X POST http://localhost:5005/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "hello world"}'
```
