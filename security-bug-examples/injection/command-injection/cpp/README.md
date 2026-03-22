# Command Injection - C++ Example

## Prerequisites

- g++ (C++17 support)
- Standard POSIX utilities (ping, dig, tail, grep, df, tar, nc, whois, traceroute)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y g++ make dnsutils netcat-openbsd whois traceroute
```

## Build

```bash
make
```

Or compile directly:

```bash
g++ -std=c++17 -Wall -Wextra -O2 -o sysadmin main.cpp
```

## Run

Show usage:

```bash
./sysadmin
```

## Example Command-Line Invocations

Ping a host:

```bash
./sysadmin ping 127.0.0.1
```

DNS lookup:

```bash
./sysadmin dns example.com A
```

Search logs:

```bash
./sysadmin logs error syslog 50
```

Show disk usage:

```bash
./sysadmin diskinfo /
```

Create an archive:

```bash
./sysadmin archive /tmp/uploads backup
```

Check port connectivity:

```bash
./sysadmin netcheck 127.0.0.1 80
```

Show system information:

```bash
./sysadmin sysinfo
```

WHOIS lookup:

```bash
./sysadmin whois example.com
```

Trace route to host:

```bash
./sysadmin traceroute 127.0.0.1
```

Interactive diagnostics mode:

```bash
./sysadmin interactive
```
