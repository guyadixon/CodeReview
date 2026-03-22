# Security Companion Document: main.rs

## Language Exclusion Note: Python and JavaScript

Python is excluded from the Integer Overflow (CWE-190) vulnerability class because Python uses arbitrary-precision integers that grow as needed to accommodate any value. There is no fixed-width integer type in standard Python, so arithmetic operations never silently overflow or wrap around, making CWE-190 impractical to demonstrate.

JavaScript is excluded because all numbers in JavaScript are IEEE 754 double-precision floating-point values. JavaScript does not have a native fixed-width integer type that wraps on overflow. While precision loss can occur with very large numbers, this manifests as floating-point rounding rather than the integer wraparound behavior described by CWE-190. The `BigInt` type provides arbitrary precision and also does not overflow.

---

## Vulnerability: Wrapping Addition in Average Computation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L35-L38

### Description
The `compute_average` method accumulates measurement values into an `i32` sum using `wrapping_add`. While `wrapping_add` prevents a panic in release mode, it silently wraps the sum on overflow, producing an incorrect average. With large sensor values (e.g., 2 billion each), the sum wraps to a negative value, and the division produces a meaningless result.

### Exploitation Scenario
An attacker provides sensor readings near `i32::MAX` (e.g., 2,000,000,000). With just two such readings, the sum wraps past `i32::MAX` to a negative value. The computed average is then negative despite all inputs being positive, leading to incorrect sensor calibration or monitoring decisions.

### Remediation Guidance
Use `i64` for the accumulator:
```rust
fn compute_average(&self) -> i64 {
    if self.measurements.is_empty() { return 0; }
    let mut sum: i64 = 0;
    for m in &self.measurements {
        sum += m.value as i64;
    }
    sum / self.measurements.len() as i64
}
```

### Complexity Rationale
This is rated Obvious because the use of `wrapping_add` explicitly signals that overflow is expected but not handled, making the vulnerability immediately visible to a reviewer familiar with Rust's integer semantics.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools and Clippy can flag `wrapping_add` usage as a potential silent overflow, and the pattern of accumulating values in a loop is well-known.

---

## Vulnerability: Wrapping Addition in Calibration Offset

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L43-L44

### Description
The `calibrated_value` method adds `calibration_offset` to a raw measurement value using `wrapping_add`. When the raw value is near `i32::MAX` and the offset is positive, the addition wraps to a negative value. The calibrated reading is then incorrect, potentially inverting the sign of the measurement.

### Exploitation Scenario
A sensor reports a raw value of 2,000,000,000 and the calibration offset is 150. The `wrapping_add` produces 2,000,000,150 which exceeds `i32::MAX` (2,147,483,647) when the raw value is closer to the limit. With a raw value of 2,147,483,600 and offset 150, the result wraps to -2,147,483,746, producing a negative calibrated value for a positive measurement.

### Remediation Guidance
Use checked arithmetic or widen to `i64`:
```rust
fn calibrated_value(&self, index: usize) -> i64 {
    let raw = self.measurements[index].value as i64;
    raw + self.calibration_offset as i64
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that both the raw value and the offset can be large, and that their sum can exceed `i32` range. The `wrapping_add` call obscures the issue by preventing panics.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must recognize that `wrapping_add` on two potentially large values produces incorrect results, requiring analysis of the value ranges of both operands.

---

## Vulnerability: Wrapping Multiplication in Power Consumption

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L48-L49

### Description
The `compute_power_consumption` method multiplies `voltage` by `current` using `wrapping_mul`. For large voltage and current values, the product exceeds `i32::MAX` and wraps silently. The resulting power value is incorrect and potentially negative.

### Exploitation Scenario
An attacker runs the program with `power 100000 100000`. The product 10,000,000,000 exceeds `i32::MAX` and wraps to a negative value. The reported power consumption is negative, which could cause monitoring systems to ignore a dangerous power condition.

### Remediation Guidance
Use `i64` for the result:
```rust
fn compute_power_consumption(&self, voltage: i32, current: i32) -> i64 {
    voltage as i64 * current as i64
}
```

### Complexity Rationale
This is rated Obvious because `wrapping_mul` on two user-provided `i32` values is a direct overflow pattern that is immediately recognizable.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools and Clippy can flag `wrapping_mul` as a potential silent overflow, and the multiplication of two user inputs is a well-known pattern.

---

## Vulnerability: Wrapping Multiplication in Sample Buffer Allocation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L52-L54

### Description
The `allocate_sample_buffer` method multiplies `sample_count` by `sample_size` using `wrapping_mul` on `u32` values, then casts the result to `usize` for the `Vec` allocation. When the product wraps (e.g., `sample_count=65536, sample_size=65536`), the wrapped value is much smaller than expected. The allocated buffer is undersized, and any subsequent writes based on the original count and size would overflow the buffer.

### Exploitation Scenario
An attacker runs `alloc 65536 65536`. The `wrapping_mul` of 65536 * 65536 wraps the `u32` result to 0, allocating a zero-length vector. Any attempt to write `sample_count * sample_size` bytes into this buffer would cause a panic or memory corruption depending on how the buffer is used downstream.

### Remediation Guidance
Use checked multiplication and validate:
```rust
fn allocate_sample_buffer(&self, sample_count: u32, sample_size: u32) -> Option<Vec<u8>> {
    let total = (sample_count as usize).checked_mul(sample_size as usize)?;
    Some(vec![0u8; total])
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that `wrapping_mul` on `u32` can produce a small value from large inputs, and that this small value is then used as an allocation size. The `as usize` cast adds another layer of indirection.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must trace the `wrapping_mul` result through the `as usize` cast into the `Vec` allocation, recognizing that the wrapped value is used as a buffer size.

---

## Vulnerability: Wrapping Arithmetic in Rate of Change Computation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L58-L67

### Description
The `compute_rate_of_change` method uses `wrapping_sub` to compute deltas between consecutive measurements and `wrapping_mul` to scale by 1000. Both operations can wrap independently. The subtraction wraps when consecutive values span a large range (e.g., from a large positive to a large negative), and the subsequent multiplication by 1000 wraps the already-incorrect delta further. The division by `time_diff` then produces a meaningless rate.

### Exploitation Scenario
Sensor readings alternate between 2,000,000,000 and -2,000,000,000. The `wrapping_sub` produces a delta of approximately 4 billion, which wraps the `i32`. The `wrapping_mul` by 1000 compounds the error. The resulting rate of change values are arbitrary, potentially masking dangerous sensor fluctuations.

### Remediation Guidance
Use `i64` for intermediate calculations:
```rust
fn compute_rate_of_change(&self) -> Vec<i64> {
    let mut deltas = Vec::new();
    for i in 1..self.measurements.len() {
        let delta = self.measurements[i].value as i64
            - self.measurements[i - 1].value as i64;
        let time_diff = self.measurements[i].timestamp as i64
            - self.measurements[i - 1].timestamp as i64;
        if time_diff > 0 {
            deltas.push(delta * 1000 / time_diff);
        }
    }
    deltas
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves two chained wrapping operations (subtraction then multiplication) where the error from the first propagates and is amplified by the second. A reviewer must trace the data flow through both operations and consider the range of consecutive measurement values.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must analyze the interaction between two separate wrapping operations in sequence, recognizing that the output of `wrapping_sub` feeds into `wrapping_mul`, and that both can independently produce incorrect results. This multi-step overflow chain is beyond typical pattern matching.

---

## Vulnerability: Wrapping Multiplication in Reading Scale

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L72-L73

### Description
The `scale_reading` method multiplies a measurement value by `factor_num` using `wrapping_mul`. For large measurement values and scale factors, the product wraps silently. The subsequent division by `factor_den` operates on the wrapped value, producing an incorrect scaled reading.

### Exploitation Scenario
An attacker runs `scale 0 3 2` with a pre-loaded measurement of 1,000,000,000. The multiplication `1000000000 * 3` produces 3,000,000,000 which exceeds `i32::MAX` and wraps. The division by 2 then produces an incorrect result, potentially half of a negative number instead of 1.5 billion.

### Remediation Guidance
Use `i64` for the intermediate calculation:
```rust
fn scale_reading(&self, index: usize, factor_num: i32, factor_den: i32) -> i64 {
    let val = self.measurements[index].value as i64;
    val * factor_num as i64 / factor_den as i64
}
```

### Complexity Rationale
This is rated Obvious because `wrapping_mul` on a measurement value and a user-provided factor is a direct overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `wrapping_mul` with user-controlled operands as a potential silent overflow.

---

## Vulnerability: Wrapping Addition in Temperature Conversion

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L100-L102

### Description
The `convert_temperature` function computes `celsius_hundredths * 9 / 5 + 3200` using `wrapping_mul` for the initial multiplication. For extreme temperature values (e.g., near `i32::MAX / 9`), the multiplication wraps. The subsequent division by 5 and addition of 3200 operate on the wrapped value, producing an incorrect Fahrenheit conversion. The vulnerability is subtle because the formula is mathematically correct but the intermediate arithmetic overflows.

### Exploitation Scenario
An attacker provides `temp 300000000` (representing 3,000,000°C in hundredths). The multiplication `300000000 * 9` produces 2,700,000,000 which exceeds `i32::MAX` and wraps. The resulting Fahrenheit value is incorrect, potentially causing a monitoring system to report a safe temperature when conditions are actually extreme.

### Remediation Guidance
Use `i64` for the conversion:
```rust
fn convert_temperature(celsius_hundredths: i32) -> i64 {
    let fahrenheit = celsius_hundredths as i64 * 9 / 5 + 3200;
    fahrenheit
}
```

### Complexity Rationale
This is rated Nuanced because the temperature conversion formula is standard and appears correct at first glance. The overflow only occurs with extreme input values, and the `wrapping_mul` call may be overlooked as a safe alternative to panicking arithmetic.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must determine that the input range for `celsius_hundredths` can cause the multiplication by 9 to overflow, which requires understanding the domain context and recognizing that `wrapping_mul` produces incorrect results rather than safe ones.
