# Integer Overflow - Rust Example

## Prerequisites

- Rust 1.70+ (via rustup)

Install on Ubuntu/Debian:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run --release
```

The application is a command-line sensor array monitor.

## Example Usage

Generate a sensor report:

```bash
cargo run --release -- report
```

Compute power consumption (triggers wrapping with large values):

```bash
cargo run --release -- power 100000 100000
```

Convert temperature:

```bash
cargo run --release -- temp 300000000
```

Scale a reading (triggers wrapping with large factor):

```bash
cargo run --release -- scale 0 3 2
```

Allocate a sample buffer (triggers wrapping with large values):

```bash
cargo run --release -- alloc 65536 65536
```

Compute a data checksum:

```bash
cargo run --release -- checksum "Hello, World!"
```
