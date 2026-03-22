# Cross-Site Scripting (XSS) - Python Example

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

The application starts a Flask web server on port 5002.

## Test the Application

Browse the forum home page:

```bash
curl http://localhost:5002/
```

Create a new post:

```bash
curl -X POST http://localhost:5002/new \
  -d "author=testuser&title=My+Post&content=Hello+world"
```

View a post:

```bash
curl http://localhost:5002/post/1
```

Add a comment:

```bash
curl -X POST http://localhost:5002/post/1/comment \
  -d "author=commenter&body=Nice+post"
```

Search posts:

```bash
curl "http://localhost:5002/search?q=welcome"
```

Preview a post:

```bash
curl -X POST http://localhost:5002/preview \
  -d "title=Test&content=Preview+content"
```

View error page:

```bash
curl "http://localhost:5002/error?msg=Something+went+wrong"
```

API endpoint with JSONP:

```bash
curl "http://localhost:5002/api/posts?callback=myCallback"
```

Save a profile:

```bash
curl -X POST http://localhost:5002/profile \
  -d "username=testuser&display_name=Test+User&bio=Hello&website=http://example.com"
```
