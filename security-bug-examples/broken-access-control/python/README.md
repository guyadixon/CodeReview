# Broken Access Control - Python Example

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

The application starts a Flask API server on port 5003.

## Test the Endpoints

Get a user profile:

```bash
curl http://localhost:5003/api/users/1
```

Update a user's salary (as manager):

```bash
curl -X PUT http://localhost:5003/api/users/3/salary \
  -H "Authorization: Bearer token_bob" \
  -H "Content-Type: application/json" \
  -d '{"salary": 75000}'
```

Get a document:

```bash
curl http://localhost:5003/api/documents/101 \
  -H "Authorization: Bearer token_alice"
```

Update a document:

```bash
curl -X PUT http://localhost:5003/api/documents/102 \
  -H "Authorization: Bearer token_bob" \
  -H "Content-Type: application/json" \
  -d '{"title": "Updated Roster"}'
```

List all users (admin):

```bash
curl http://localhost:5003/api/admin/users \
  -H "Authorization: Bearer token_alice" \
  -H "X-User-Role: admin"
```

Update a user's role:

```bash
curl -X PUT http://localhost:5003/api/users/3/role \
  -H "Authorization: Bearer token_alice" \
  -H "Content-Type: application/json" \
  -d '{"role": "manager"}'
```

Debug configuration:

```bash
curl http://localhost:5003/api/debug/config
```
