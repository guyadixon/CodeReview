# Use After Free - C++ Example

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
./doc-store
```

The application is a command-line document store utility.

## Example Usage

Access a document after removal (dangling pointer):

```bash
./doc-store dangling
```

Fire events for removed documents:

```bash
./doc-store events
```

Fetch a document snapshot:

```bash
./doc-store snapshot
```

Double free document content:

```bash
./doc-store doublefree
```

Build a document index with dynamic buffer:

```bash
./doc-store index
```

Merge all document contents:

```bash
./doc-store merge
```

List all documents:

```bash
./doc-store list
```
