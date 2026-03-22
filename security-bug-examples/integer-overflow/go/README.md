# Integer Overflow - Go Example

## Prerequisites

- Go 1.21+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install the latest version from the official site:

```bash
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

## Build

```bash
go build -o booking-system main.go
```

## Run

```bash
./booking-system
```

The application is a command-line hotel booking system.

## Example Usage

Generate a sample invoice:

```bash
./booking-system invoice
```

Compute a seasonal rate (triggers overflow with large values):

```bash
./booking-system seasonal 2000000000 150
```

Compute a group discount:

```bash
./booking-system group 5000000 20
```

Compute loyalty points (triggers overflow with large spend):

```bash
./booking-system loyalty 2000000000 5
```

Convert currency (triggers truncation with large amounts):

```bash
./booking-system convert 2000000000 1500000
```

Allocate a room block (triggers overflow with large values):

```bash
./booking-system alloc 131072 32768
```

Compute occupancy rate:

```bash
./booking-system occupancy 85 100
```
