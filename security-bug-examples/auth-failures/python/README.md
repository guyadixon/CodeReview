# Auth Failures - Python Example

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

The application starts a Flask API server on port 5004.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:5004/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

Verify a token:

```bash
curl -X POST http://localhost:5004/api/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE"}'
```

Request password reset:

```bash
curl -X POST http://localhost:5004/api/password-reset \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@acmecorp.io"}'
```

Confirm password reset:

```bash
curl -X POST http://localhost:5004/api/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "new_password": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:5004/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

List users:

```bash
curl http://localhost:5004/api/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Deactivate a user:

```bash
curl -X POST http://localhost:5004/api/users/3/deactivate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
