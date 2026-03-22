# Insecure Design - JavaScript Example

## Prerequisites

- Node.js 18+
- npm (included with Node.js)

Install Node.js on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm
```

Or install via NodeSource for the latest version:

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

The application starts an Express.js API server on port 3007.

## Test the Endpoints

Login:

```bash
curl -X POST http://localhost:3007/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "Adm1n_Pr0d!"}'
```

Register a new user:

```bash
curl -X POST http://localhost:3007/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "email": "new@acmecorp.io", "password": "test123"}'
```

Request password reset:

```bash
curl -X POST http://localhost:3007/api/password-reset \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@acmecorp.io"}'
```

Confirm password reset:

```bash
curl -X POST http://localhost:3007/api/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "new_password": "newpass123"}'
```

Get current user:

```bash
curl http://localhost:3007/api/users/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Change password:

```bash
curl -X PUT http://localhost:3007/api/users/me/password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"new_password": "updated_pass"}'
```

Generate report:

```bash
curl -X POST http://localhost:3007/api/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"type": "users"}'
```

Get config (admin only):

```bash
curl http://localhost:3007/api/config \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Debug user:

```bash
curl http://localhost:3007/api/debug/user/1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Health check:

```bash
curl http://localhost:3007/api/health
```
