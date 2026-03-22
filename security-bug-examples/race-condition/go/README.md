# Race Condition - Go Example

## Prerequisites

- Go 1.21+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official Go website:

```bash
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

## Build

```bash
go build -o race-demo main.go
```

## Run

```bash
./race-demo <command> [args...]
```

The application is a command-line utility demonstrating concurrent simulations.

## Example Usage

Bank transfer simulation with 4 goroutines and 100 iterations:

```bash
./race-demo bank 4 100
```

Ticket booking simulation with 4 goroutines and 100 tickets:

```bash
./race-demo tickets 4 100
```

Inventory simulation with 4 goroutines and 200 items:

```bash
./race-demo inventory 4 200
```

Singleton config simulation with 8 goroutines:

```bash
./race-demo singleton 8
```

Shared counter simulation with 4 goroutines and 100 increments each:

```bash
./race-demo counter 4 100
```

To detect races at runtime, use Go's built-in race detector:

```bash
go run -race main.go bank 4 100
```
