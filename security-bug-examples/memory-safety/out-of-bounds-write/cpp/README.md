# Out-of-bounds Write - C++ Example

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
./sensor-log
```

The application is a command-line sensor logging utility.

## Example Usage

Log a sensor reading:

```bash
./sensor-log log 1 "temp_sensor" 23.5
```

Generate a report:

```bash
./sensor-log report
```

Process a data pipeline:

```bash
./sensor-log pipeline "1.0,2.5,3.7,4.2"
```

Process tagged input:

```bash
./sensor-log tagged "sensor:temperature_reading_42"
```

Aggregate readings:

```bash
./sensor-log aggregate "10.5,20.3,15.8,30.1"
```

Add a prefix to text:

```bash
./sensor-log prefix "lab" "measurement_001"
```
