# Integer Overflow - C Example

## Prerequisites

- GCC or Clang (C11+)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y gcc make
```

## Build

```bash
make
```

## Run

```bash
./invoice-calc
```

The application is a command-line invoice calculator.

## Example Usage

Generate an invoice report with a discount:

```bash
./invoice-calc invoice 15
```

Calculate shipping cost (triggers overflow with large values):

```bash
./invoice-calc shipping 100000 50000
```

Convert currency:

```bash
./invoice-calc convert 2000000000 1500000
```

Process a bulk order:

```bash
./invoice-calc bulk "Widget" 50000 99999 10
```

Allocate an item buffer (triggers overflow with large values):

```bash
./invoice-calc alloc 65536 65536
```

Compute a data checksum:

```bash
./invoice-calc checksum "Hello, World!"
```
