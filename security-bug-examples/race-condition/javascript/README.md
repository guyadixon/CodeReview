# Race Condition - JavaScript Example

## Prerequisites

- Node.js 18+

Install on Ubuntu/Debian:

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
node app.js <command> [args...]
```

The application is a command-line utility demonstrating async concurrency race conditions.

## Example Usage

Bank transfer simulation with 4 concurrent tasks and 100 iterations:

```bash
node app.js bank 4 100
```

Ticket booking simulation with 4 concurrent tasks and 100 tickets:

```bash
node app.js tickets 4 100
```

Inventory simulation with 4 concurrent tasks and 200 items:

```bash
node app.js inventory 4 200
```

Singleton config simulation with 8 concurrent tasks:

```bash
node app.js singleton 8
```

File-based counter simulation with 4 concurrent tasks:

```bash
node app.js filecounter 4
```
