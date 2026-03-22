# Out-of-bounds Write - C Example

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
./record-store
```

The application is a command-line record store utility.

## Example Usage

Add a record:

```bash
./record-store add "sensor_alpha" 42.5
```

Update the store description:

```bash
./record-store desc "Production" "Warehouse-A"
```

Process comma-separated values:

```bash
./record-store values "1.0,2.5,3.7,4.2,5.8"
```

Merge fields:

```bash
./record-store merge "field_one" "field_two" "field_three"
```

List record names:

```bash
./record-store names
```

List all records:

```bash
./record-store list
```
