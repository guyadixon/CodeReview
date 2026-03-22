# Race Condition - Python Example

## Prerequisites

- Python 3.10+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y python3
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Run

```bash
python3 app.py <command> [args...]
```

The application is a command-line utility demonstrating concurrent simulations.

## Example Usage

Bank transfer simulation with 4 threads and 100 iterations:

```bash
python3 app.py bank 4 100
```

Ticket booking simulation with 4 threads and 100 tickets:

```bash
python3 app.py tickets 4 100
```

Inventory management simulation with 4 threads and 200 items:

```bash
python3 app.py inventory 4 200
```

Singleton config simulation with 8 threads:

```bash
python3 app.py config 8
```

File-based counter simulation with 4 threads:

```bash
python3 app.py filecounter 4
```
