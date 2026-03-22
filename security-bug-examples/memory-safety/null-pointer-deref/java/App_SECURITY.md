# Security Companion Document: App.java

## Language Exclusion Note: Python, JavaScript, and Rust

Python and JavaScript are excluded from the NULL Pointer Dereference (CWE-476) vulnerability class because these languages do not expose raw pointers. In Python, accessing an attribute on `None` raises an `AttributeError` exception that can be caught and handled, preventing undefined behavior or memory corruption. Similarly, in JavaScript, accessing a property on `null` or `undefined` raises a `TypeError` exception. While these exceptions can cause application crashes if unhandled, they do not produce the memory-safety consequences (segmentation faults, undefined behavior, potential code execution) that characterize CWE-476 in languages with raw pointers.

Rust is excluded because its type system prevents null pointer dereferences at compile time. Rust has no null value for references; instead, it uses the `Option<T>` enum to represent values that may or may not exist. The compiler forces the programmer to handle the `None` case before accessing the inner value, making it impossible to dereference a null pointer in safe Rust code. While `unsafe` blocks can create raw pointers, idiomatic Rust code avoids this pattern entirely.

---

## Vulnerability: NullPointerException in processOrder for Unknown SKU

**CWE:** CWE-476
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L100-L101

### Description
The `OrderProcessor.processOrder` method calls `inventory.findBySku(sku)` which returns `null` when the SKU does not exist in the inventory (since `HashMap.get` returns `null` for missing keys). The method then calls `product.getStockCount()` on the null reference, causing a `NullPointerException`.

### Exploitation Scenario
An attacker runs `java App order NONEXISTENT 5`. The `findBySku("NONEXISTENT")` call returns `null`, and `product.getStockCount()` throws a `NullPointerException`. In a production inventory system, this crash could disrupt order processing and cause a denial-of-service for legitimate customers.

### Remediation Guidance
Check the return value of `findBySku` before use:
```java
String processOrder(String sku, int quantity) {
    Product product = inventory.findBySku(sku);
    if (product == null) {
        return String.format("Product not found: %s", sku);
    }
    int available = product.getStockCount();
    // ... rest of method
}
```

### Complexity Rationale
This is rated Obvious because the `findBySku` call and the unchecked dereference occur on consecutive lines, and `HashMap.get` returning `null` for missing keys is a well-known Java pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the return value of `findBySku` (which delegates to `HashMap.get`, a known nullable return) directly to the method call on the next line without any intervening null check.

---

## Vulnerability: NullPointerException in calculatePrice from Null Double Unboxing

**CWE:** CWE-476
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L82-L83

### Description
The `PriceCalculator.calculatePrice` method calls `discountRules.get(product.getCategory())` which returns a `Double` (boxed type). When the product's category has no discount rule, the map returns `null`. The expression `discount / 100.0` triggers auto-unboxing of the null `Double` to a primitive `double`, causing a `NullPointerException`.

### Exploitation Scenario
An attacker runs `java App price SKU-004`. The Desk Lamp product has category "furniture", but the `PriceCalculator` only has discount rules for "electronics" and "stationery". The `discountRules.get("furniture")` call returns `null`, and the auto-unboxing in `discount / 100.0` throws a `NullPointerException`. An attacker who can query prices for products in unconfigured categories can crash the price calculation service.

### Remediation Guidance
Use `getOrDefault` or check for null before unboxing:
```java
double calculatePrice(Product product) {
    Double discount = discountRules.get(product.getCategory());
    if (discount == null) {
        return product.getPrice();
    }
    return product.getPrice() * (1.0 - discount / 100.0);
}
```

### Complexity Rationale
This is rated Obvious because the map lookup and the arithmetic expression that triggers unboxing are on consecutive lines, and the null-to-primitive unboxing pattern is a well-documented Java pitfall.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can recognize that `HashMap.get` returns a nullable `Double`, and the subsequent arithmetic operation forces auto-unboxing, which is a known NPE pattern that many tools specifically check for.

---

## Vulnerability: NullPointerException in applyPriceUpdate for Unknown SKU

**CWE:** CWE-476
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L170-L173

### Description
The `applyPriceUpdate` method iterates over parsed property entries and calls `inventory.findBySku(entry.getKey())` for each. When a property key does not match any product SKU, `findBySku` returns `null`. The method then calls `product.setPrice(newPrice)` and `product.getName()` on the null reference, causing a `NullPointerException`.

### Exploitation Scenario
An attacker runs `java App update "FAKE-SKU=19.99"`. The `findBySku("FAKE-SKU")` call returns `null`, and `product.setPrice(newPrice)` throws a `NullPointerException`. In a system where price updates come from an external feed or configuration file, an attacker who can inject entries with invalid SKUs can crash the update process, preventing legitimate price changes from being applied.

### Remediation Guidance
Check for null before updating:
```java
static void applyPriceUpdate(Inventory inventory, String input) {
    Map<String, String> updates = parseProperties(input);
    for (Map.Entry<String, String> entry : updates.entrySet()) {
        Product product = inventory.findBySku(entry.getKey());
        if (product == null) {
            System.err.printf("Product not found: %s%n", entry.getKey());
            continue;
        }
        double newPrice = Double.parseDouble(entry.getValue());
        product.setPrice(newPrice);
        System.out.printf("Updated %s price to $%.2f%n", product.getName(), newPrice);
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans a loop that processes parsed input, requiring the reviewer to understand that `parseProperties` can produce keys that do not correspond to valid SKUs, and that `findBySku` returns null for such keys. The null dereference is separated from the lookup by a `Double.parseDouble` call.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the data flow from user input through `parseProperties` to the map iteration, then through `findBySku` to the null dereference. The intermediate parsing step and loop iteration add complexity to the taint analysis.

---

## Vulnerability: NullPointerException in generateStockReport from Null Integer Unboxing

**CWE:** CWE-476
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L140-L141

### Description
The `generateStockReport` method iterates over all products and formats each with `String.format` using `%d` for `p.getStockCount()`. The `stockCount` field is declared as `Integer` (boxed type), and the product "Desk Lamp" (SKU-004) is initialized with `null` for its stock count. When `String.format` encounters the `%d` format specifier with a null `Integer`, auto-unboxing triggers a `NullPointerException`.

### Exploitation Scenario
An attacker runs `java App stock`. The report generation iterates over all products, including SKU-004 which has a null stock count. The `String.format` call with `%d` and `p.getStockCount()` (which returns null) triggers auto-unboxing, throwing a `NullPointerException`. This crashes the stock report generation, preventing inventory visibility. The vulnerability is triggered by normal application usage, not just adversarial input, because the null stock count is part of the seed data.

### Remediation Guidance
Handle the nullable Integer before formatting:
```java
String generateStockReport() {
    StringBuilder sb = new StringBuilder();
    sb.append("Stock Report\n");
    sb.append("============\n");
    for (Product p : inventory.getAllProducts()) {
        int stock = p.getStockCount() != null ? p.getStockCount() : 0;
        sb.append(String.format("  %s (%s): %d units @ $%.2f\n",
                p.getName(), p.getSku(), stock, p.getPrice()));
    }
    return sb.toString();
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that `stockCount` is a boxed `Integer` (not primitive `int`), that one product in the seed data has a null value for this field, and that `String.format` with `%d` forces auto-unboxing. The null value is set during initialization in a separate method (`populateInventory`), not at the point of use.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the `Integer` type through the `getStockCount()` accessor, recognize that `String.format` with `%d` triggers auto-unboxing, and ideally trace the null value from the `populateInventory` method. Many tools detect nullable returns but may not flag the auto-unboxing in `String.format` specifically.

---

## Vulnerability: NullPointerException in findMostExpensive via Optional.of(null) Anti-Pattern

**CWE:** CWE-476
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L63-L69

### Description
The `Inventory.findMostExpensive` method checks `products.isEmpty()` and returns `Optional.empty()` for the empty case. For the non-empty case, it uses `Optional.of(stream.max(...).orElse(null))`. The `orElse(null)` call returns `null` if the stream produces no maximum (which can happen if the collection is modified between the `isEmpty()` check and the stream operation in a concurrent context). Passing `null` to `Optional.of()` throws a `NullPointerException` — unlike `Optional.ofNullable()` which safely wraps null values. Even in a single-threaded context, this pattern is a latent defect: if the `isEmpty()` guard is ever removed or the method is refactored, the `Optional.of(null)` will immediately throw NPE. The use of `Optional.of` instead of `Optional.ofNullable` combined with `orElse(null)` is a well-known Java anti-pattern that introduces a hidden null-safety gap.

### Exploitation Scenario
In a concurrent inventory system where products can be added and removed by multiple threads, an attacker triggers a race condition: one thread removes all products between the `isEmpty()` check and the stream operation. The stream finds no maximum, `orElse(null)` returns `null`, and `Optional.of(null)` throws a `NullPointerException`. Even without concurrency, if a future code change removes the `isEmpty()` guard (since the developer assumes Optional handles the empty case), calling `findMostExpensive()` on an empty inventory immediately throws NPE instead of returning `Optional.empty()`.

### Remediation Guidance
Use `Optional.ofNullable` or restructure to avoid the anti-pattern:
```java
Optional<Product> findMostExpensive() {
    return products.values().stream()
            .max(Comparator.comparingDouble(Product::getPrice));
}
```
This directly returns the `Optional` from `max()`, which is `Optional.empty()` when the stream is empty, eliminating both the manual emptiness check and the `Optional.of(null)` risk.

### Complexity Rationale
This is rated Nuanced because the code appears to handle the empty case correctly with the `isEmpty()` guard, and the `Optional.of(orElse(null))` pattern looks superficially correct. A reviewer must understand the semantic difference between `Optional.of` (which throws on null) and `Optional.ofNullable` (which wraps null), recognize that `orElse(null)` can produce null, and reason about whether the `isEmpty()` guard is sufficient to prevent this. The vulnerability is a latent defect that manifests under concurrency or code evolution.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not flag `Optional.of()` as a potential NPE source, since it is a standard library method. The `isEmpty()` guard satisfies most null-safety analyses, and recognizing that `orElse(null)` combined with `Optional.of` creates a hidden NPE requires understanding the semantic contract of the Optional API. Most tools focus on direct null dereferences rather than library method contracts.
