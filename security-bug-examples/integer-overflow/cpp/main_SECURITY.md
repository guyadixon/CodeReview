# Security Companion Document: main.cpp

## Language Exclusion Note: Python and JavaScript

Python is excluded from the Integer Overflow (CWE-190) vulnerability class because Python uses arbitrary-precision integers that grow as needed to accommodate any value. There is no fixed-width integer type in standard Python, so arithmetic operations never silently overflow or wrap around, making CWE-190 impractical to demonstrate.

JavaScript is excluded because all numbers in JavaScript are IEEE 754 double-precision floating-point values. JavaScript does not have a native fixed-width integer type that wraps on overflow. While precision loss can occur with very large numbers, this manifests as floating-point rounding rather than the integer wraparound behavior described by CWE-190. The `BigInt` type provides arbitrary precision and also does not overflow.

---

## Vulnerability: Integer Overflow in Transaction Fee Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L33-L34

### Description
The `compute_fee` method multiplies `txn.amount_cents` by `txn.fee_basis_points`, both `int` (32-bit signed). For large transaction amounts (e.g., 87,500,000 cents) with moderate fee rates (e.g., 75 basis points), the intermediate product can approach or exceed `INT_MAX`, causing signed integer overflow which is undefined behavior in C++.

### Exploitation Scenario
An attacker submits a transaction with `amount_cents=2000000000` and `fee_basis_points=200`. The multiplication `2000000000 * 200` produces 400,000,000,000 which overflows a 32-bit signed integer. The resulting fee could be negative or incorrect, causing the net amount to exceed the original transaction amount.

### Remediation Guidance
Use 64-bit arithmetic for the multiplication:
```cpp
int64_t compute_fee(const Transaction &txn) const {
    return static_cast<int64_t>(txn.amount_cents) * txn.fee_basis_points / 10000;
}
```

### Complexity Rationale
This is rated Obvious because multiplying two `int` values without widening is a textbook integer overflow pattern immediately recognizable during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify `int * int` multiplication patterns and flag potential overflow when neither operand is cast to a wider type.

---

## Vulnerability: Integer Overflow in Portfolio Value Accumulation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L41-L47

### Description
The `compute_portfolio_value` method accumulates net transaction values into an `int total` starting from `balance_cents`. Each `compute_net` call returns an `int`, and the running sum can overflow when the opening balance plus multiple large net amounts exceeds `INT_MAX`.

### Exploitation Scenario
A portfolio with an opening balance of 1,000,000 cents and four transactions each netting around 500,000,000 cents produces a total exceeding 2 billion, overflowing `INT_MAX`. The resulting negative portfolio value could trigger incorrect business logic decisions such as margin calls or account freezes.

### Remediation Guidance
Use a 64-bit accumulator:
```cpp
int64_t compute_portfolio_value(const Portfolio &portfolio) const {
    int64_t total = portfolio.balance_cents;
    for (const auto &txn : portfolio.transactions) {
        total += compute_net(txn);
    }
    return total;
}
```

### Complexity Rationale
This is rated Moderate because the overflow depends on the cumulative effect of multiple additions across transactions, requiring the reviewer to consider the range of values from `compute_net` and the initial balance.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to determine that `compute_net` can return large values and that accumulating them in an `int` can overflow.

---

## Vulnerability: Integer Overflow in Record Buffer Allocation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L50-L51

### Description
The `allocate_record_buffer` method casts `record_count` to `size_t` but multiplies it by `record_size` which remains an `int`. When `record_size` is negative (from user input via `std::stoi`), the multiplication with a `size_t` value produces an unexpectedly large allocation due to unsigned wraparound. Additionally, if both values are large positive integers, the multiplication can wrap in `size_t` on 32-bit systems.

### Exploitation Scenario
An attacker runs `./ledger-engine alloc 2 -1`. The `record_count` (2) is cast to `size_t`, but `record_size` (-1) is implicitly converted to a very large `size_t` value. The multiplication produces an enormous allocation request. Alternatively, with `./ledger-engine alloc 1000000 1000000`, the product may wrap on 32-bit systems, allocating a small buffer while `memset` writes the full expected size.

### Remediation Guidance
Validate inputs and perform checked multiplication:
```cpp
void *allocate_record_buffer(int record_count, int record_size) const {
    if (record_count <= 0 || record_size <= 0) return nullptr;
    size_t total = static_cast<size_t>(record_count) * static_cast<size_t>(record_size);
    if (total / record_size != static_cast<size_t>(record_count)) return nullptr;
    void *buffer = malloc(total);
    if (buffer) memset(buffer, 0, total);
    return buffer;
}
```

### Complexity Rationale
This is rated Obvious because using user-controlled integers as `malloc` size arguments without validation is a well-known overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools commonly flag arithmetic used in allocation sizes, especially when operands come from user input.

---

## Vulnerability: Integer Overflow in Compound Interest Loop

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L59-L66

### Description
The `compute_compound_interest` method iteratively computes `current * rate_bp / 10000` and adds the result to `current`. Over many periods, `current` grows exponentially. Since `current` is an `int`, it overflows when the compounded value exceeds `INT_MAX`. The overflow can occur silently mid-loop, producing incorrect results for all subsequent iterations.

### Exploitation Scenario
An attacker runs `./ledger-engine interest 1000000000 500 100`. Starting with 1 billion cents at 5% per period for 100 periods, the value doubles roughly every 14 periods. After about 15 iterations, `current` exceeds `INT_MAX` and wraps to a negative value. Subsequent iterations compound the error, producing a wildly incorrect final amount.

### Remediation Guidance
Use 64-bit arithmetic and add overflow detection:
```cpp
int64_t compute_compound_interest(int64_t principal_cents, int rate_bp, int periods) const {
    int64_t current = principal_cents;
    for (int i = 0; i < periods; i++) {
        int64_t interest = current * rate_bp / 10000;
        current += interest;
    }
    return current;
}
```

### Complexity Rationale
This is rated Moderate because the overflow occurs gradually over multiple loop iterations rather than in a single operation, requiring the reviewer to reason about exponential growth and the number of periods needed to trigger overflow.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must analyze the loop to determine that `current` grows monotonically and can exceed `INT_MAX` after sufficient iterations, requiring loop-aware overflow analysis.

---

## Vulnerability: Signed Overflow in 16-bit Hash Computation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L69-L73

### Description
The `compute_short_hash` method uses an `int16_t` accumulator with the expression `hash * 31 + static_cast<int16_t>(c)`. The multiplication `hash * 31` is performed in `int` arithmetic (due to integer promotion), but the result is stored back into `int16_t`, truncating to 16 bits. While the truncation itself is implementation-defined, the repeated multiply-and-add cycle produces unpredictable hash values that can collide easily, and the signed overflow of `int16_t` is undefined behavior when the promoted result exceeds `INT16_MAX`.

### Exploitation Scenario
An attacker crafts input strings that produce hash collisions by exploiting the 16-bit wraparound. Since the hash space is only 65,536 values, collision attacks are trivial. If the hash is used for any security-sensitive purpose (e.g., integrity checking, deduplication), an attacker can forge data that produces the same hash as legitimate data.

### Remediation Guidance
Use a wider hash type and unsigned arithmetic:
```cpp
uint32_t compute_hash(const std::string &data) const {
    uint32_t hash = 0;
    for (char c : data) {
        hash = hash * 31 + static_cast<uint8_t>(c);
    }
    return hash;
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves understanding integer promotion rules in C++, the difference between signed and unsigned overflow behavior, and the security implications of a narrow hash space. The code appears to function correctly for short inputs.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not flag `int16_t` arithmetic as overflow-prone, and the integer promotion to `int` followed by narrowing back to `int16_t` is a subtle pattern that most tools do not analyze.

---

## Vulnerability: Integer Overflow in Amount Scaling

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L77-L79

### Description
The `scale_amount` method computes `amount * numerator / denominator` using `int` arithmetic. The intermediate product `amount * numerator` can overflow when both values are large. For example, scaling a large transaction amount by a numerator greater than 1 easily exceeds `INT_MAX`.

### Exploitation Scenario
An attacker runs `./ledger-engine scale 2000000000 3 2`. The multiplication `2000000000 * 3` produces 6,000,000,000 which overflows a 32-bit signed integer. The wrapped result divided by 2 produces an incorrect scaled amount, potentially causing financial miscalculation.

### Remediation Guidance
Use 64-bit arithmetic:
```cpp
int64_t scale_amount(int amount, int numerator, int denominator) const {
    return static_cast<int64_t>(amount) * numerator / denominator;
}
```

### Complexity Rationale
This is rated Obvious because multiplying two `int` values from user input without widening is a straightforward overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify the `int * int` pattern where operands come from user input and flag the potential overflow.
