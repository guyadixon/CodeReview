# Security Companion Document: main.go

## Language Exclusion Note: Python and JavaScript

Python is excluded from the Integer Overflow (CWE-190) vulnerability class because Python uses arbitrary-precision integers that grow as needed to accommodate any value. There is no fixed-width integer type in standard Python, so arithmetic operations never silently overflow or wrap around, making CWE-190 impractical to demonstrate.

JavaScript is excluded because all numbers in JavaScript are IEEE 754 double-precision floating-point values. JavaScript does not have a native fixed-width integer type that wraps on overflow. While precision loss can occur with very large numbers, this manifests as floating-point rounding rather than the integer wraparound behavior described by CWE-190. The `BigInt` type provides arbitrary precision and also does not overflow.

---

## Vulnerability: Integer Overflow in Room Charge Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L38-L39

### Description
The `ComputeRoomCharge` method multiplies `r.RoomRate` by `r.Nights`, both `int32`. For high room rates over many nights (e.g., rate=250000 cents/night for 21 nights), the product can approach or exceed the `int32` maximum of 2,147,483,647. Go silently wraps signed integer overflow, producing an incorrect charge.

### Exploitation Scenario
An attacker books a reservation with `RoomRate=250000` and `Nights=21`, producing a product of 5,250,000 which fits. However, with `RoomRate=250000` and `Nights=10000`, the product 2,500,000,000 exceeds `int32` max and wraps to a negative value. The guest is charged a negative amount, effectively receiving a credit.

### Remediation Guidance
Use `int64` for the calculation:
```go
func (bs *BookingSystem) ComputeRoomCharge(r Reservation) int64 {
    return int64(r.RoomRate) * int64(r.Nights)
}
```

### Complexity Rationale
This is rated Obvious because multiplying two `int32` values without widening is a textbook integer overflow pattern immediately recognizable during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify `int32 * int32` multiplication patterns and flag potential overflow.

---

## Vulnerability: Integer Overflow in Tax Computation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L42-L44

### Description
The `ComputeTax` method computes `charge * r.TaxBP / 10000` where `charge` is the result of `ComputeRoomCharge`. The intermediate multiplication `charge * r.TaxBP` can overflow `int32` when the room charge is large. Since `charge` itself may already be near `int32` max, multiplying by even a small tax rate (e.g., 1200 basis points) causes overflow.

### Exploitation Scenario
A reservation with a room charge of 2,000,000,000 cents and a tax rate of 1200 basis points produces the multiplication `2000000000 * 1200` = 2,400,000,000,000 which overflows `int32`. The wrapped tax value could be negative, reducing the total instead of increasing it.

### Remediation Guidance
Use `int64` for intermediate arithmetic:
```go
func (bs *BookingSystem) ComputeTax(r Reservation) int64 {
    charge := bs.ComputeRoomCharge(r)
    return charge * int64(r.TaxBP) / 10000
}
```

### Complexity Rationale
This is rated Moderate because the overflow depends on the return value of `ComputeRoomCharge`, requiring interprocedural reasoning to determine that `charge` can be large enough to cause overflow when multiplied by the tax rate.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the data flow from `ComputeRoomCharge` through the multiplication to recognize the overflow potential.

---

## Vulnerability: Integer Overflow in Total Computation with Addition

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L47-L50

### Description
The `ComputeTotal` method adds `charge` and `tax`, both `int32` values. When both are large (e.g., charge near 2 billion and tax near 200 million), their sum exceeds `int32` max and wraps. Additionally, the `charge` and `tax` values may themselves be incorrect due to upstream overflow in `ComputeRoomCharge` and `ComputeTax`.

### Exploitation Scenario
A reservation produces a charge of 1,800,000,000 cents and a tax of 500,000,000 cents. The sum 2,300,000,000 exceeds `int32` max and wraps to a negative value. The guest's total bill is negative, resulting in a credit instead of a charge.

### Remediation Guidance
Use `int64` throughout the computation chain:
```go
func (bs *BookingSystem) ComputeTotal(r Reservation) int64 {
    charge := bs.ComputeRoomCharge(r)
    tax := bs.ComputeTax(r)
    return charge + tax
}
```

### Complexity Rationale
This is rated Moderate because the overflow is the result of two upstream computations being added together, requiring the reviewer to reason about the combined range of both values.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must analyze the return types and ranges of both `ComputeRoomCharge` and `ComputeTax` to determine that their sum can overflow `int32`.

---

## Vulnerability: Integer Overflow in Seasonal Rate Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L53-L54

### Description
The `ComputeSeasonalRate` method multiplies `baseRate` by `bs.SeasonFactor`, both `int32`. For high base rates with a season factor above 100 (e.g., 150 for peak season), the product can exceed `int32` max. The subsequent division by 100 operates on the wrapped value.

### Exploitation Scenario
An attacker runs `seasonal 2000000000 150`. The multiplication `2000000000 * 150` produces 300,000,000,000 which overflows `int32`. The wrapped result divided by 100 produces an incorrect seasonal rate.

### Remediation Guidance
Use `int64` for the multiplication:
```go
func (bs *BookingSystem) ComputeSeasonalRate(baseRate int32) int64 {
    return int64(baseRate) * int64(bs.SeasonFactor) / 100
}
```

### Complexity Rationale
This is rated Obvious because multiplying two `int32` values from user input without widening is a straightforward overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify the `int32 * int32` pattern where operands come from user input.

---

## Vulnerability: Integer Overflow in Room Block Allocation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L66-L72

### Description
The `AllocateRoomBlock` method multiplies `rooms` by `dataPerRoom`, both `int32`. The product can overflow to a small positive value or a negative value. The negative check (`totalSize < 0`) catches some overflow cases but not all — when the overflow produces a small positive value, the check passes and a tiny buffer is allocated. The caller expects a buffer sized for `rooms * dataPerRoom` bytes.

### Exploitation Scenario
An attacker runs `alloc 131072 32768`. The product `131072 * 32768` = 4,294,967,296 which overflows `int32` to 0. The check `totalSize < 0` passes (0 is not negative), and `make([]byte, 0)` creates an empty slice. Any subsequent writes based on the expected size would panic or corrupt memory.

### Remediation Guidance
Use `int64` and validate properly:
```go
func (bs *BookingSystem) AllocateRoomBlock(rooms int32, dataPerRoom int32) []byte {
    total := int64(rooms) * int64(dataPerRoom)
    if total <= 0 || total > math.MaxInt32 {
        return nil
    }
    return make([]byte, total)
}
```

### Complexity Rationale
This is rated Moderate because the code includes a negative check that appears to guard against overflow, but the check is insufficient. A reviewer must understand that `int32` overflow can produce small positive values that bypass the guard.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must recognize that the negative check is an incomplete overflow guard and that the `int32` multiplication can produce false-positive small values.

---

## Vulnerability: Integer Overflow in Loyalty Points Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L74-L75

### Description
The `ComputeLoyaltyPoints` method multiplies `spendCents` by `multiplier`, both `int32`. For high-spending customers with large multipliers, the product exceeds `int32` max. The subsequent division by 100 operates on the wrapped value, producing incorrect loyalty points.

### Exploitation Scenario
An attacker runs `loyalty 2000000000 5`. The multiplication `2000000000 * 5` produces 10,000,000,000 which overflows `int32`. The wrapped result divided by 100 produces an incorrect (potentially negative) loyalty points value.

### Remediation Guidance
Use `int64` for the multiplication:
```go
func (bs *BookingSystem) ComputeLoyaltyPoints(spendCents int32, multiplier int32) int64 {
    return int64(spendCents) * int64(multiplier) / 100
}
```

### Complexity Rationale
This is rated Obvious because multiplying two `int32` values from user input without widening is a direct overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can flag `int32 * int32` multiplication with user-controlled operands.

---

## Vulnerability: Truncation in Currency Conversion Result

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L103-L105

### Description
The `convertCurrency` function correctly uses `int64` for the intermediate multiplication, but truncates the result back to `int32` on the return. When the converted amount exceeds `int32` max (2,147,483,647), the cast `int32(intermediate / 1000000)` silently truncates the 64-bit result, producing an incorrect value. This is subtle because the intermediate calculation is correct but the final narrowing loses data.

### Exploitation Scenario
An attacker runs `convert 2000000000 1500000` to convert 2 billion cents at a rate of 1.5. The intermediate result is 3,000,000,000,000,000 / 1,000,000 = 3,000,000,000 which exceeds `int32` max. The truncation wraps the result to a negative value, producing an incorrect converted amount.

### Remediation Guidance
Return `int64`:
```go
func convertCurrency(amountCents int32, rateMillionths int32) int64 {
    intermediate := int64(amountCents) * int64(rateMillionths)
    return intermediate / 1000000
}
```

### Complexity Rationale
This is rated Nuanced because the function appears to handle overflow correctly by using `int64` for the intermediate calculation, but the narrowing cast on the return is easy to overlook. A reviewer must recognize that the 64-bit result can exceed 32-bit range after division.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically focus on the multiplication overflow pattern and may not flag the narrowing conversion from `int64` to `int32` on the return, especially since the intermediate calculation is correctly widened.
