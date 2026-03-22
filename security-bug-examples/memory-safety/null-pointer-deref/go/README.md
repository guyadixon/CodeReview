# NULL Pointer Dereference - Go Example

## Prerequisites

- Go 1.21+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y golang-go
```

Or install from the official Go website:

```bash
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

## Install Dependencies

No external dependencies required. The application uses only the Go standard library.

```bash
go mod download
```

## Build

```bash
go build -o metric-monitor main.go
```

## Run

```bash
./metric-monitor
```

The application is a command-line metric monitoring utility.

## Example Usage

Generate a metrics report:

```bash
./metric-monitor report
```

Compare two metrics:

```bash
./metric-monitor compare cpu_usage memory_used
```

Compare with a nonexistent metric (triggers nil dereference):

```bash
./metric-monitor compare cpu_usage nonexistent_metric
```

Sum metric values:

```bash
./metric-monitor sum "cpu_usage,memory_used,disk_io"
```

Find the maximum metric:

```bash
./metric-monitor max "cpu_usage,memory_used,disk_io"
```

Ingest new metric data:

```bash
./metric-monitor ingest "new_metric 42.5 1700000010 host=web-02"
```

Filter metrics by tag:

```bash
./metric-monitor filter host web-01
```

Render the dashboard (triggers nil dereference for missing widget):

```bash
./metric-monitor dashboard
```

List all metrics:

```bash
./metric-monitor list
```
