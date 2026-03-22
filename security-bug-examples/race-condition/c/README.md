# Race Condition - C Example

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
./race-demo <command> [args...]
```

The application is a command-line utility demonstrating concurrent simulations using pthreads.

## Example Usage

Bank transfer simulation with 4 threads and 100 iterations:

```bash
./race-demo bank 4 100
```

Ticket booking simulation with 4 threads and 100 tickets:

```bash
./race-demo tickets 4 100
```

Shared counter simulation with 4 threads and 1000 increments each:

```bash
./race-demo counter 4 1000
```

Inventory simulation with 4 threads and 200 items:

```bash
./race-demo inventory 4 200
```

Singleton config simulation with 8 threads:

```bash
./race-demo singleton 8
```

To detect races at runtime, compile with ThreadSanitizer:

```bash
gcc -fsanitize=thread -g -o race-demo main.c -lpthread
./race-demo bank 4 100
```
