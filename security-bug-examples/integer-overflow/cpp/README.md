# Integer Overflow - C++ Example

## Prerequisites

- g++ or clang++ (C++17+)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make
```

## Build

```bash
make
```

## Run

```bash
./ledger-engine
```

The application is a command-line financial ledger engine.

## Example Usage

Generate a portfolio statement:

```bash
./ledger-engine portfolio
```

Compute compound interest (triggers overflow with large principal/periods):

```bash
./ledger-engine interest 1000000000 500 100
```

Compute a transaction fee:

```bash
./ledger-engine fee 2000000000 200
```

Scale an amount (triggers overflow with large values):

```bash
./ledger-engine scale 2000000000 3 2
```

Allocate a record buffer:

```bash
./ledger-engine alloc 65536 65536
```

Compute a short hash:

```bash
./ledger-engine hash "test data"
```
