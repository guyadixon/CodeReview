# Auth Failures - JavaScript Example

## Prerequisites

- Node.js 18+
- npm

Install Node.js on Ubuntu/Debian:

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

The application starts an Express.js API server on port 3004.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:3004/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin2024!"}'
```

Validate a token:

```bash
curl -X POST http://localhost:3004/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE"}'
```

Request password reset:

```bash
curl -X POST http://localhost:3004/api/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@taskflow.io"}'
```

Reset password:

```bash
curl -X POST http://localhost:3004/api/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "newPassword": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:3004/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

List users:

```bash
curl http://localhost:3004/api/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Support login:

```bash
curl -X POST http://localhost:3004/api/support/login \
  -H "Content-Type: application/json" \
  -d '{"escalationCode": "CODE", "targetUserId": 1}'
```

Deactivate a user:

```bash
curl -X POST http://localhost:3004/api/users/3/deactivate \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
