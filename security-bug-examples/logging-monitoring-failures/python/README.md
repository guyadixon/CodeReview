# Logging/Monitoring Failures - Python Example

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

The application starts a Flask API server on port 5009.

## Test the Endpoints

Health check:

```bash
curl http://localhost:5009/api/health
```

Login:

```bash
curl -X POST http://localhost:5009/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

List users (use token from login response):

```bash
curl http://localhost:5009/api/admin/users \
  -H "Authorization: Bearer <token>"
```

Create a transaction:

```bash
curl -X POST http://localhost:5009/api/transactions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"amount": 500.00, "recipient": "vendor@example.com", "description": "Payment"}'
```

Export data:

```bash
curl -X POST http://localhost:5009/api/export/data \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "users"}'
```

Toggle MFA:

```bash
curl -X PUT http://localhost:5009/api/settings/mfa \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"enabled": false}'
```
