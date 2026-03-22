# NULL Pointer Dereference - Java Example

## Prerequisites

- JDK 17+
- Apache Maven 3.8+

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven
```

## Install Dependencies

No external dependencies required. The application uses only the Java standard library.

```bash
mvn dependency:resolve
```

## Build

Using Maven:

```bash
mvn compile
mvn package -q
```

Or compile directly with javac:

```bash
javac App.java
```

## Run

Using the compiled class:

```bash
java -cp . App
```

Or using the Maven-built JAR:

```bash
java -jar target/null-pointer-deref-1.0.0.jar
```

The application is a command-line inventory management utility.

## Example Usage

Generate a stock report (triggers NPE for null stock count):

```bash
java -cp . App stock
```

Process an order for a known product:

```bash
java -cp . App order SKU-001 5
```

Process an order for a nonexistent SKU (triggers NPE):

```bash
java -cp . App order NONEXISTENT 3
```

Generate a category report:

```bash
java -cp . App category electronics
```

Calculate discounted price for a product with a discount rule:

```bash
java -cp . App price SKU-001
```

Calculate discounted price for a product without a discount rule (triggers NPE):

```bash
java -cp . App price SKU-004
```

Find the most expensive product:

```bash
java -cp . App expensive
```

Update prices from properties input:

```bash
java -cp . App update "SKU-001=24.99"
```

Update with a nonexistent SKU (triggers NPE):

```bash
java -cp . App update "FAKE-SKU=19.99"
```

List all products:

```bash
java -cp . App list
```
