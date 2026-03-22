# Use After Free - C Example

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
./task-manager
```

The application is a command-line task manager utility.

## Example Usage

Complete and remove a task (demonstrates dangling pointer access):

```bash
./task-manager complete
```

Register notifications and fire after removal:

```bash
./task-manager notify
```

Build a task summary with dynamic buffer:

```bash
./task-manager summary
```

Duplicate the first task entry:

```bash
./task-manager duplicate
```

Archive completed tasks:

```bash
./task-manager archive
```
