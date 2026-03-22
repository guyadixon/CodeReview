# Command Injection - Python Example

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

The application starts a Flask API server on port 5001.

## Test the Endpoints

Ping a host:

```bash
curl "http://localhost:5001/api/ping?host=127.0.0.1"
```

DNS lookup:

```bash
curl "http://localhost:5001/api/dns/lookup?domain=example.com&type=A"
```

List files:

```bash
curl "http://localhost:5001/api/files/list?path=/tmp"
```

Create an archive:

```bash
curl -X POST http://localhost:5001/api/files/archive \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/uploads", "name": "backup"}'
```

Search logs:

```bash
curl "http://localhost:5001/api/logs/search?keyword=error&file=syslog&lines=50"
```

System information:

```bash
curl "http://localhost:5001/api/system/info"
```

Check port connectivity:

```bash
curl -X POST http://localhost:5001/api/network/check \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1", "port": 80}'
```
