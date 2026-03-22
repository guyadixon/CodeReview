# Command Injection - Java Example

## Prerequisites

- JDK 17+
- Maven 3.6+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven
```

## Build

```bash
mvn clean package -f pom.xml
```

## Run

```bash
java -jar target/sysadmin-api-1.0.0.jar
```

The application starts a Spring Boot API server on port 8081.

## Test the Endpoints

Ping a host:

```bash
curl "http://localhost:8081/api/ping?host=127.0.0.1"
```

DNS lookup:

```bash
curl "http://localhost:8081/api/dns/lookup?domain=example.com&type=A"
```

Search logs:

```bash
curl "http://localhost:8081/api/logs/search?keyword=error&file=syslog&lines=50"
```

List files:

```bash
curl "http://localhost:8081/api/files/list?path=/tmp"
```

Create an archive:

```bash
curl -X POST http://localhost:8081/api/files/archive \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/uploads", "name": "backup"}'
```

Check port connectivity:

```bash
curl -X POST http://localhost:8081/api/network/check \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1", "port": 80}'
```

System information:

```bash
curl "http://localhost:8081/api/system/info"
```

Check certificate:

```bash
curl "http://localhost:8081/api/certs/check?hostname=example.com&port=443"
```
