# Out-of-bounds Write - Rust Example

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
cargo run --release -- <command> [args...]
```

The application is a command-line inventory management utility using unsafe Rust.

## Example Usage

Add an inventory item:

```bash
cargo run --release -- add "widget_alpha" 50 12.99
```

Pack float values into binary format:

```bash
cargo run --release -- pack "1.0,2.5,3.7,4.2"
```

Scale values by a factor:

```bash
cargo run --release -- scale "10.0,20.0,30.0" 1.5
```

Merge strings:

```bash
cargo run --release -- merge "part_one" "part_two" "part_three"
```

Build an inventory index:

```bash
cargo run --release -- index
```

List inventory:

```bash
cargo run --release -- list
```
