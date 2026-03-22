# Race Condition - Rust Example

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

Or compile directly:

```bash
rustc main.rs -o race-demo
```

## Run

```bash
./race-demo <command> [args...]
```

Or via Cargo:

```bash
cargo run -- <command> [args...]
```

The application is a command-line utility demonstrating concurrent simulations using unsafe shared mutable state.

## Example Usage

Bank balance simulation with 4 threads and 100 iterations:

```bash
cargo run -- bank 4 100
```

Ticket booking simulation with 4 threads and 100 tickets:

```bash
cargo run -- tickets 4 100
```

Shared counter simulation with 4 threads and 1000 increments each:

```bash
cargo run -- counter 4 1000
```

Global config singleton simulation with 8 threads:

```bash
cargo run -- singleton 8
```

Inventory simulation with 4 threads and 200 items:

```bash
cargo run -- inventory 4 200
```
