# Integer Overflow - Java Example

## Prerequisites

- JDK 17+
- Maven 3.6+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven
```

## Build

Using Maven:

```bash
mvn compile
mvn package
```

Or compile directly:

```bash
javac App.java
```

## Run

Using Maven:

```bash
java -cp target/classes App
```

Or if compiled directly:

```bash
java App
```

The application is a command-line payroll engine.

## Example Usage

Generate a payroll report:

```bash
java App payroll
```

Compute a bonus (triggers overflow with large salary):

```bash
java App bonus 2000000000 10
```

Compute retirement contribution (triggers overflow chain):

```bash
java App retire 2000000000 100 80
```

Allocate a paystub buffer (triggers overflow with large values):

```bash
java App alloc 131072 32768
```

Compute next paycheck number (triggers short overflow):

```bash
java App checknum 32000 1000
```

Compute gross pay:

```bash
java App grosspay 1000 95000 200
```
