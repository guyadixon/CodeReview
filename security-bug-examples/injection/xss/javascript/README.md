# Cross-Site Scripting (XSS) - JavaScript Example

## Prerequisites

- Node.js 18+
- npm (included with Node.js)

Install Node.js on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm
```

Or install via NodeSource:

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

## Install Dependencies

```bash
npm install
```

## Run

```bash
node app.js
```

The application starts an Express.js web server on port 3002.

## Test the Application

Browse the home page:

```bash
curl http://localhost:3002/
```

Filter by tag:

```bash
curl "http://localhost:3002/?tag=welcome"
```

View a post:

```bash
curl http://localhost:3002/post/1
```

Create a new post:

```bash
curl -X POST http://localhost:3002/new \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "author=testuser&title=My+Post&content=Hello+world&tags=test,js"
```

Add a comment:

```bash
curl -X POST http://localhost:3002/post/1/comment \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "author=commenter&body=Nice+post"
```

Search posts:

```bash
curl "http://localhost:3002/search?q=welcome"
```

View error page:

```bash
curl "http://localhost:3002/error?msg=Something+went+wrong"
```

Save a profile:

```bash
curl -X POST http://localhost:3002/profile \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&display_name=Test+User&bio=Hello&website=http://example.com"
```

API endpoint with JSONP:

```bash
curl "http://localhost:3002/api/posts?callback=myCallback"
```

Embed widget:

```bash
curl "http://localhost:3002/embed?title=My+Widget&theme=light"
```
