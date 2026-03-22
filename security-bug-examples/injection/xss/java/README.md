# Cross-Site Scripting (XSS) - Java Example

## Prerequisites

- JDK 17+
- Maven 3.6+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven
```

## Install Dependencies and Build

```bash
mvn clean package -DskipTests
```

## Run

```bash
java -jar target/xss-blog-1.0.0.jar
```

The application starts a Spring Boot web server on port 8084.

## Test the Application

Browse the blog home page:

```bash
curl http://localhost:8084/
```

Filter by category:

```bash
curl "http://localhost:8084/?category=tutorial"
```

View a post:

```bash
curl http://localhost:8084/post/1
```

Write a new post:

```bash
curl -X POST http://localhost:8084/write \
  -d "author=testuser&title=My+Post&content=Hello+world&category=general"
```

Add a comment:

```bash
curl -X POST http://localhost:8084/post/1/comment \
  -d "author=commenter&body=Great+post"
```

Search posts:

```bash
curl "http://localhost:8084/search?q=welcome"
```

View error page:

```bash
curl "http://localhost:8084/error?msg=Something+went+wrong"
```

Save a profile:

```bash
curl -X POST http://localhost:8084/profile \
  -d "username=testuser&display_name=Test+User&bio=Hello&website=http://example.com&avatar_url=http://example.com/avatar.png"
```

API endpoint with JSONP:

```bash
curl "http://localhost:8084/api/posts?callback=myCallback"
```
