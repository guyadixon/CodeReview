# NULL Pointer Dereference - C Example

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
./config-manager
```

The application is a command-line configuration manager utility.

## Example Usage

Look up a configuration value:

```bash
./config-manager lookup database_host
```

Look up a nonexistent key (triggers null dereference):

```bash
./config-manager lookup nonexistent_key
```

Merge two configuration values:

```bash
./config-manager merge database_host database_port
```

Export all configurations:

```bash
./config-manager export
```

Load configurations from key=value input:

```bash
./config-manager load "new_key=new_value"
```

Process batch commands:

```bash
./config-manager batch "get database_host;len cache_ttl;del log_level"
```

List all configurations:

```bash
./config-manager list
```
