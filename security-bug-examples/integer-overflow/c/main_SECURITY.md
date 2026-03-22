# Security Companion Document: main.c

## Language Exclusion Note: Python and JavaScript

Python is excluded from the Integer Overflow (CWE-190) vulnerability class because Python uses arbitrary-precision integers that grow as needed to accommodate any value. There is no fixed-width integer type in standard Python, so arithmetic operations never silently overflow or wrap around, making CWE-190 impractical to demonstrate.

JavaScript is excluded because all numbers in JavaScript are IEEE 754 double-precision floating-point values. JavaScript does not have a native fixed-width integer type that wraps on overflow. While precision loss can occur with very large numbers, this manifests as floating-point rounding rather than the integer wraparound behavior described by CWE-190. The `BigInt` type provides arbitrary precision and also does not overflow.

---

## Vulnerability: Integer Overflow in Line Item Total Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L42-L43

### Description
The `compute_line_total` function multiplies `item->quantity` by `item->unit_price_cents`, both `int` (32-bit signed). When both values are large (e.g., quantity=500, price=99999 cents), the product can exceed `INT_MAX` (2,147,483,647), causing signed integer overflow which is undefined behavior in C.

### Exploitation Scenario
An attacker runs `./invoice-calc invoice 0` with the default items. The "Enterprise License" line has quantity=500 and unit_price_cents=99999, producing a product of 49,999,500 which fits. However, if the application is modified or inputs are provided with larger values (e.g., quantity=50000, price=99999), the multiplication overflows, producing a negative or incorrect total that could result in undercharging or financial miscalculation.

### Remediation Guidance
Use 64-bit arithmetic for the multiplication:
```c
static long long compute_line_total(const LineItem *item) {
    return (long long)item->quantity * item->unit_price_cents;
}
```

### Complexity Rationale
This is rated Obvious because multiplying two `int` values without widening is a textbook integer overflow pattern that is immediately recognizable during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify `int * int` multiplication patterns where neither operand is cast to a wider type, and flag potential overflow.

---

## Vulnerability: Integer Overflow in Subtotal Accumulation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L45-L51

### Description
The `compute_subtotal` function accumulates line totals into an `int subtotal` variable. Each call to `compute_line_total` returns an `int`, and the running sum can overflow when multiple large line items are added together. The overflow is compounded because each individual line total may already be near the `int` limit.

### Exploitation Scenario
An attacker creates an invoice with many high-value items. For example, three items each with a line total near 1 billion cents would produce a subtotal exceeding `INT_MAX`. The resulting negative subtotal could cause the discount calculation to produce unexpected results, potentially generating a credit instead of a charge.

### Remediation Guidance
Use a 64-bit accumulator:
```c
static long long compute_subtotal(const Invoice *inv) {
    long long subtotal = 0;
    for (int i = 0; i < inv->count; i++) {
        subtotal += compute_line_total(&inv->items[i]);
    }
    return subtotal;
}
```

### Complexity Rationale
This is rated Moderate because the overflow depends on the cumulative effect of multiple additions, requiring the reviewer to consider the range of values returned by `compute_line_total` across all items rather than a single operation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to determine that the return value of `compute_line_total` can be large, and that accumulating multiple such values in an `int` can overflow.

---

## Vulnerability: Integer Overflow in Discount Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L53-L55

### Description
The `apply_discount` function computes `amount * discount_percent / 100`. The intermediate multiplication `amount * discount_percent` can overflow when `amount` is a large subtotal. Since `amount` is the result of `compute_subtotal` (which itself can be large), the multiplication with `discount_percent` (up to 100) can easily exceed `INT_MAX`.

### Exploitation Scenario
An attacker creates a bulk order with a subtotal of 1.5 billion cents and applies a 50% discount. The multiplication `1500000000 * 50` produces 75,000,000,000 which overflows a 32-bit signed integer. The wrapped result could produce a negative discount, effectively increasing the total instead of reducing it.

### Remediation Guidance
Cast to 64-bit before multiplication:
```c
static long long apply_discount(long long amount, int discount_percent) {
    long long discount = amount * discount_percent / 100;
    return amount - discount;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that `amount` can be very large (it comes from `compute_subtotal`) and that multiplying it by `discount_percent` overflows, requiring cross-function reasoning.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must trace the data flow from `compute_subtotal` through `apply_discount` to recognize that the `amount` parameter can hold values large enough to cause overflow when multiplied.

---

## Vulnerability: Integer Overflow in Buffer Size Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L57-L58

### Description
The `allocate_buffer` function computes `item_count * item_size` using `int` arithmetic before casting to `size_t`. If both parameters are large (e.g., item_count=65536, item_size=65536), the multiplication overflows the 32-bit `int`, wrapping to a small or negative value. The cast to `size_t` then produces an incorrect allocation size, and the subsequent `memset` writes beyond the allocated buffer.

### Exploitation Scenario
An attacker runs `./invoice-calc alloc 65536 65536`. The multiplication `65536 * 65536` overflows a 32-bit int to 0. The `malloc(0)` returns a minimal allocation (or NULL on some systems), but `memset` writes 0 bytes (since total is 0 after overflow), which may appear benign. With carefully chosen values like `item_count=131072, item_size=32768`, the overflow produces a small positive value, causing `malloc` to allocate a tiny buffer while the caller expects a large one.

### Remediation Guidance
Perform the multiplication in `size_t` and validate:
```c
static void *allocate_buffer(int item_count, int item_size) {
    if (item_count <= 0 || item_size <= 0) return NULL;
    size_t total = (size_t)item_count * (size_t)item_size;
    if (total / item_size != (size_t)item_count) return NULL;
    void *buf = malloc(total);
    if (buf) memset(buf, 0, total);
    return buf;
}
```

### Complexity Rationale
This is rated Obvious because multiplying two user-controlled `int` values and using the result as a `malloc` size is a well-known integer overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools commonly flag `int * int` used as a `malloc` argument, especially when the operands come from user input.

---

## Vulnerability: Integer Overflow in Shipping Cost Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L68-L71

### Description
The `compute_shipping` function multiplies `weight_grams` by `distance_km` to compute `base_cost`. Both are `int` parameters from user input. For large shipments over long distances (e.g., weight=100000, distance=50000), the product 5,000,000,000 exceeds `INT_MAX`, causing signed integer overflow. The subsequent surcharge calculation (`base_cost / 10`) and addition compound the error.

### Exploitation Scenario
An attacker runs `./invoice-calc shipping 100000 50000`. The multiplication overflows, potentially producing a negative `base_cost`. The surcharge calculation on a negative base produces a negative surcharge, and the final shipping cost is incorrect. This could result in a negative shipping charge (credit) for a legitimate heavy, long-distance shipment.

### Remediation Guidance
Use 64-bit arithmetic:
```c
static long long compute_shipping(int weight_grams, int distance_km) {
    long long base_cost = (long long)weight_grams * distance_km;
    long long surcharge = base_cost / 10;
    return base_cost + surcharge;
}
```

### Complexity Rationale
This is rated Moderate because while the multiplication pattern is straightforward, the reviewer must consider realistic input ranges for weight and distance to determine whether overflow is plausible, and must trace the cascading effect through the surcharge calculation.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that both parameters come from user input (`argv`) and that their product can exceed 32-bit range, requiring taint analysis from command-line arguments through the multiplication.

---

## Vulnerability: Truncation in Currency Conversion Result

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L93-L96

### Description
The `convert_currency` function correctly uses `long long` for the intermediate multiplication, but truncates the result back to `int` on the return. When the converted amount exceeds `INT_MAX`, the cast `(int)(intermediate / 1000000)` silently truncates the 64-bit result to 32 bits, producing an incorrect value. This is a subtle overflow because the intermediate calculation is correct but the final narrowing conversion loses data.

### Exploitation Scenario
An attacker runs `./invoice-calc convert 2000000000 1500000` to convert 2 billion cents at a rate of 1.5. The intermediate result is 3,000,000,000,000,000 / 1,000,000 = 3,000,000,000, which exceeds `INT_MAX`. The truncation to `int` wraps the result to a negative value, producing an incorrect converted amount.

### Remediation Guidance
Return `long long` and validate the range:
```c
static long long convert_currency(int amount_cents, int exchange_rate_millionths) {
    long long intermediate = (long long)amount_cents * exchange_rate_millionths;
    return intermediate / 1000000;
}
```

### Complexity Rationale
This is rated Nuanced because the function appears to handle overflow correctly by using `long long` for the intermediate calculation, but the narrowing cast on the return is easy to overlook. A reviewer must recognize that the 64-bit result can exceed 32-bit range after division.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically focus on the multiplication overflow pattern and may not flag the narrowing conversion from `long long` to `int` on the return, especially since the intermediate calculation is correctly widened.

---

## Vulnerability: Unchecked Narrowing in parse_quantity

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L99-L101

### Description
The `parse_quantity` function uses `strtol` which returns a `long` (64-bit on most Linux systems), then casts the result to `int` without range checking. Values exceeding `INT_MAX` or below `INT_MIN` are silently truncated, producing incorrect quantities that propagate through all subsequent calculations including line totals and subtotals.

### Exploitation Scenario
An attacker runs `./invoice-calc bulk "Widget" 3000000000 100`. The `strtol` correctly parses 3,000,000,000 as a `long`, but the cast to `int` truncates it to -1,294,967,296 (on a 32-bit int system). This negative quantity propagates through `compute_line_total`, producing a negative line total that reduces the invoice total, effectively creating a credit.

### Remediation Guidance
Validate the range after parsing:
```c
static int parse_quantity(const char *str) {
    long val = strtol(str, NULL, 10);
    if (val > INT_MAX || val < INT_MIN) {
        fprintf(stderr, "Quantity out of range\n");
        return 0;
    }
    return (int)val;
}
```

### Complexity Rationale
This is rated Nuanced because the function uses the correct parsing function (`strtol`) and the narrowing cast appears routine. The reviewer must understand that `long` is wider than `int` on 64-bit systems and that the truncation can produce arbitrary values.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools often do not flag `long` to `int` narrowing conversions, especially when `strtol` is used correctly for parsing. The truncation is a semantic issue rather than a syntactic pattern.
