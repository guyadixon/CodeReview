# NULL Pointer Dereference - C++ Example

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
./sensor-monitor
```

The application is a command-line sensor monitoring utility.

## Example Usage

Generate a sensor report:

```bash
./sensor-monitor report
```

Evaluate alert rules (triggers null dereference for missing sensor):

```bash
./sensor-monitor alert
```

Compare two sensors:

```bash
./sensor-monitor compare 1 2
```

Compare with a nonexistent sensor (triggers null dereference):

```bash
./sensor-monitor compare 1 999
```

Find the maximum reading:

```bash
./sensor-monitor max
```

Ingest new sensor readings:

```bash
./sensor-monitor ingest "10 55.3 1700000010 celsius"
```

Compute average across sensors:

```bash
./sensor-monitor average
```

List all registered sensors:

```bash
./sensor-monitor list
```
