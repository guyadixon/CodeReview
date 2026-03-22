# Security Companion Document: App.java

## Language Exclusion Note: Python and JavaScript

Python is excluded from the Integer Overflow (CWE-190) vulnerability class because Python uses arbitrary-precision integers that grow as needed to accommodate any value. There is no fixed-width integer type in standard Python, so arithmetic operations never silently overflow or wrap around, making CWE-190 impractical to demonstrate.

JavaScript is excluded because all numbers in JavaScript are IEEE 754 double-precision floating-point values. JavaScript does not have a native fixed-width integer type that wraps on overflow. While precision loss can occur with very large numbers, this manifests as floating-point rounding rather than the integer wraparound behavior described by CWE-190. The `BigInt` type provides arbitrary precision and also does not overflow.

---

## Vulnerability: Integer Overflow in Gross Pay Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L33-L39

### Description
The `computeGrossPay` method computes overtime pay as `overtimeHours * entry.hourlyRateCents * entry.overtimeMultiplierPct / 100`. The chained multiplication of three `int` values can overflow. For employees with many overtime hours and high hourly rates, the intermediate product `overtimeHours * hourlyRateCents` can exceed `Integer.MAX_VALUE` before the multiplier is applied. Java silently wraps signed integer overflow.

### Exploitation Scenario
An employee entry has `hoursWorked=168`, `hourlyRateCents=45000`, and `overtimeMultiplierPct=150`. The overtime hours are 128, and the multiplication `128 * 45000 * 150` = 864,000,000 which fits. However, with `hourlyRateCents=95000` and `hoursWorked=60`, overtime is 20 hours: `20 * 95000 * 200` = 380,000,000 which also fits. But with extreme values like `hoursWorked=1000, hourlyRateCents=95000, overtimeMultiplierPct=200`, the product `960 * 95000 * 200` = 18,240,000,000 overflows `int`, producing an incorrect (potentially negative) gross pay.

### Remediation Guidance
Use `long` for intermediate calculations:
```java
long computeGrossPay(TimeEntry entry) {
    long regularHours = Math.min(entry.hoursWorked, 40);
    long overtimeHours = Math.max(entry.hoursWorked - 40, 0);
    long regularPay = regularHours * entry.hourlyRateCents;
    long overtimePay = overtimeHours * entry.hourlyRateCents
            * entry.overtimeMultiplierPct / 100;
    return regularPay + overtimePay;
}
```

### Complexity Rationale
This is rated Moderate because the overflow involves a three-operand multiplication chain where the reviewer must consider the combined range of hours, rate, and multiplier to determine whether overflow is possible. The regular/overtime split adds complexity.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must trace the chained multiplication of three `int` values and determine that their combined product can exceed `Integer.MAX_VALUE`, requiring multi-operand overflow analysis.

---

## Vulnerability: Integer Overflow in Tax Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L42-L43

### Description
The `computeTax` method multiplies `grossCents` by `taxRateBP` (both `int`). When `grossCents` is large (from `computeGrossPay`), the product `grossCents * taxRateBP` can exceed `Integer.MAX_VALUE`. With a tax rate of 2200 basis points (22%), even a gross pay of 1 billion cents causes the multiplication to overflow.

### Exploitation Scenario
An employee's gross pay is computed as 1,500,000,000 cents. The tax calculation `1500000000 * 2200` = 3,300,000,000,000 which overflows `int`. The resulting negative tax is subtracted from gross pay in `computeNetPay`, producing a net pay higher than the gross pay.

### Remediation Guidance
Use `long` for the multiplication:
```java
long computeTax(long grossCents) {
    return grossCents * taxRateBP / 10000;
}
```

### Complexity Rationale
This is rated Obvious because multiplying two `int` values without widening is a textbook integer overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify `int * int` multiplication patterns and flag potential overflow.

---

## Vulnerability: Integer Overflow in Total Payroll Accumulation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L52-L57

### Description
The `computeTotalPayroll` method accumulates gross pay values into an `int total`. Each `computeGrossPay` call returns an `int`, and the running sum can overflow when multiple employees with high gross pay are processed. The overflow is compounded because individual gross pay values may already be near the `int` limit.

### Exploitation Scenario
Four employees each have a gross pay near 600 million cents. The running total reaches 2.4 billion after four additions, exceeding `Integer.MAX_VALUE` and wrapping to a negative value. The reported total payroll is negative, which could cause payroll processing systems to malfunction.

### Remediation Guidance
Use a `long` accumulator:
```java
long computeTotalPayroll() {
    long total = 0;
    for (TimeEntry entry : entries) {
        total += computeGrossPay(entry);
    }
    return total;
}
```

### Complexity Rationale
This is rated Moderate because the overflow depends on the cumulative effect of multiple additions, requiring the reviewer to consider the number of entries and the range of values returned by `computeGrossPay`.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to determine that `computeGrossPay` can return large values and that accumulating them in an `int` can overflow.

---

## Vulnerability: Integer Overflow in Bonus Calculation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L60-L63

### Description
The `computeBonus` method computes `baseSalary * bonusPct / 100` where `baseSalary` is an `int` from user input. When `baseSalary` is large and `bonusPct` is up to 50 (capped), the product `baseSalary * 50` can exceed `Integer.MAX_VALUE`. For example, a base salary of 100,000,000 cents (1 million dollars) with a 50% bonus produces 5,000,000,000 which overflows.

### Exploitation Scenario
An attacker runs `bonus 2000000000 10`. The bonus percentage is `10 * 5 = 50` (capped at 50). The multiplication `2000000000 * 50` = 100,000,000,000 overflows `int`. The wrapped result divided by 100 produces an incorrect bonus amount.

### Remediation Guidance
Use `long` for the multiplication:
```java
long computeBonus(int baseSalary, int performanceScore) {
    int bonusPct = performanceScore * 5;
    if (bonusPct > 50) bonusPct = 50;
    return (long) baseSalary * bonusPct / 100;
}
```

### Complexity Rationale
This is rated Obvious because multiplying a user-provided `int` by a percentage without widening is a straightforward overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can identify the `int * int` pattern where one operand comes from user input.

---

## Vulnerability: Integer Overflow in Paystub Buffer Allocation

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L66-L71

### Description
The `allocatePaystubBuffer` method multiplies `employeeCount` by `bytesPerStub`, both `int`. The product can overflow to a small positive value or a negative value. The negative check (`totalSize < 0`) catches some overflow cases but not all — when the overflow produces a small positive value, the check passes and a tiny `byte[]` is allocated. The caller expects a buffer sized for `employeeCount * bytesPerStub` bytes.

### Exploitation Scenario
An attacker runs `alloc 131072 32768`. The product `131072 * 32768` = 4,294,967,296 which overflows `int` to 0. The check `totalSize < 0` passes (0 is not negative), and `new byte[0]` creates an empty array. Any subsequent writes based on the expected size would throw `ArrayIndexOutOfBoundsException` or produce incorrect results.

### Remediation Guidance
Use `long` and validate properly:
```java
byte[] allocatePaystubBuffer(int employeeCount, int bytesPerStub) {
    long totalSize = (long) employeeCount * bytesPerStub;
    if (totalSize <= 0 || totalSize > Integer.MAX_VALUE) return null;
    return new byte[(int) totalSize];
}
```

### Complexity Rationale
This is rated Moderate because the code includes a negative check that appears to guard against overflow, but the check is insufficient. A reviewer must understand that `int` overflow can produce small positive values that bypass the guard.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must recognize that the negative check is an incomplete overflow guard and that the `int` multiplication can produce false-positive small values.

---

## Vulnerability: Short Integer Overflow in Paycheck Number

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L74-L75

### Description
The `computePaycheckNumber` method adds two `short` values and casts the result back to `short`. Java promotes `short` operands to `int` for arithmetic, and the explicit cast `(short)(lastNumber + increment)` truncates the `int` result to 16 bits. When the sum exceeds `Short.MAX_VALUE` (32767), the truncation wraps to a negative value, producing an invalid paycheck number.

### Exploitation Scenario
An attacker runs `checknum 32000 1000`. The sum `32000 + 1000` = 33000 exceeds `Short.MAX_VALUE` (32767). The cast to `short` wraps to -32536. The paycheck numbering system produces a negative number, potentially causing duplicate paycheck numbers or processing errors.

### Remediation Guidance
Use `int` for paycheck numbers:
```java
int computePaycheckNumber(int lastNumber, int increment) {
    return lastNumber + increment;
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves understanding Java's integer promotion rules (short is promoted to int for arithmetic) and the explicit narrowing cast back to short. The `short` type is rarely used in Java, making this pattern unfamiliar to many reviewers.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not flag `short` arithmetic as overflow-prone, and the explicit cast `(short)` appears intentional. The narrowing from `int` to `short` is a semantic issue that most tools do not analyze for overflow.

---

## Vulnerability: Integer Overflow in Retirement Contribution

**CWE:** CWE-190
**OWASP:** null
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L78-L82

### Description
The `computeRetirementContribution` method computes `annualSalary * employeeContribPct / 100` followed by `employeeContrib * matchPct / 100`. The first multiplication can overflow when `annualSalary` is large. The second multiplication compounds the error if `employeeContrib` is already incorrect from the first overflow. The final addition `employeeContrib + employerMatch` can also overflow. This creates a chain of three potential overflow points.

### Exploitation Scenario
An attacker runs `retire 2000000000 100 50`. The employee contribution is `2000000000 * 50 / 100` = 1,000,000,000. The employer match is `1000000000 * 100 / 100` = 1,000,000,000. The total `1000000000 + 1000000000` = 2,000,000,000 which fits. But with `retire 2000000000 100 80`, the employee contribution is `2000000000 * 80 / 100` — but the intermediate `2000000000 * 80` = 160,000,000,000 overflows `int`, producing an incorrect contribution that cascades through the match and total calculations.

### Remediation Guidance
Use `long` throughout:
```java
long computeRetirementContribution(int annualSalary, int matchPct, int employeeContribPct) {
    long employeeContrib = (long) annualSalary * employeeContribPct / 100;
    long employerMatch = employeeContrib * matchPct / 100;
    return employeeContrib + employerMatch;
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves a chain of three dependent calculations where overflow in the first propagates through the second and third. A reviewer must trace the data flow through all three operations and consider the combined effect of the input parameters.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must analyze a multi-step computation chain where each step depends on the previous result, recognizing that overflow in the first multiplication cascades through subsequent calculations. This chained overflow pattern is beyond typical single-operation analysis.
