# Race Condition - Java Example

## Prerequisites

- JDK 17+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk
```

## Build

```bash
javac App.java
```

## Run

```bash
java App <command> [args...]
```

The application is a command-line utility demonstrating concurrent simulations.

## Example Usage

Bank transfer simulation with 4 threads and 100 iterations:

```bash
java App bank 4 100
```

Ticket booking simulation with 4 threads and 100 tickets:

```bash
java App tickets 4 100
```

Shared counter simulation with 4 threads and 1000 increments each:

```bash
java App counter 4 1000
```

Singleton config simulation with 8 threads:

```bash
java App singleton 8
```

Inventory simulation with 4 threads and 200 items:

```bash
java App inventory 4 200
```
