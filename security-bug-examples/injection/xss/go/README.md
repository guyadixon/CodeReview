# Cross-Site Scripting (XSS) - Go Example

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
go build -o techboard main.go
```

## Run

```bash
./techboard
```

The application starts a Gin web server on port 8085.

## Test the Application

Browse the home page:

```bash
curl http://localhost:8085/
```

Filter by tag:

```bash
curl "http://localhost:8085/?tag=welcome"
```

View a post:

```bash
curl http://localhost:8085/post/1
```

Create a new post:

```bash
curl -X POST http://localhost:8085/new \
  -d "author=testuser&title=My+Post&content=Hello+world&tags=test,go"
```

Add a comment:

```bash
curl -X POST http://localhost:8085/post/1/comment \
  -d "author=commenter&body=Nice+post"
```

Search posts:

```bash
curl "http://localhost:8085/search?q=welcome"
```

View error page:

```bash
curl "http://localhost:8085/error?msg=Something+went+wrong"
```

Save a profile:

```bash
curl -X POST http://localhost:8085/profile \
  -d "username=testuser&display_name=Test+User&bio=Hello&website=http://example.com"
```

API endpoint with JSONP:

```bash
curl "http://localhost:8085/api/posts?callback=myCallback"
```
