# Security Companion Document: main.go

## Language Exclusion Note: Python, JavaScript, and Rust

Python and JavaScript are excluded from the NULL Pointer Dereference (CWE-476) vulnerability class because these languages do not expose raw pointers. In Python, accessing an attribute on `None` raises an `AttributeError` exception that can be caught and handled, preventing undefined behavior or memory corruption. Similarly, in JavaScript, accessing a property on `null` or `undefined` raises a `TypeError` exception. While these exceptions can cause application crashes if unhandled, they do not produce the memory-safety consequences (segmentation faults, undefined behavior, potential code execution) that characterize CWE-476 in languages with raw pointers.

Rust is excluded because its type system prevents null pointer dereferences at compile time. Rust has no null value for references; instead, it uses the `Option<T>` enum to represent values that may or may not exist. The compiler forces the programmer to handle the `None` case before accessing the inner value, making it impossible to dereference a null pointer in safe Rust code. While `unsafe` blocks can create raw pointers, idiomatic Rust code avoids this pattern entirely.

---

## Vulnerability: Nil Pointer Dereference in Aggregator.Sum

**CWE:** CWE-476
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L72-L75

### Description
The `Aggregator.Sum` method iterates over metric names and calls `store.Get(name)` for each. When a name does not exist in the store, `Get` returns `nil` (the zero value for a map lookup on `map[string]*Metric`). The method then accesses `m.Value` without checking for `nil`, causing a nil pointer dereference panic.

### Exploitation Scenario
An attacker runs `./metric-monitor sum "cpu_usage,nonexistent_metric"`. The `Get("nonexistent_metric")` call returns `nil`, and `m.Value` triggers a Go runtime panic with `runtime error: invalid memory address or nil pointer dereference`. This crashes the monitoring application. An attacker who can control the metric names passed to the sum command can reliably trigger a denial-of-service.

### Remediation Guidance
Check for nil before accessing the metric value:
```go
func (a *Aggregator) Sum(names []string) float64 {
    total := 0.0
    for _, name := range names {
        m := a.store.Get(name)
        if m == nil {
            continue
        }
        total += m.Value
    }
    return total
}
```

### Complexity Rationale
This is rated Obvious because the `Get` call and the unchecked dereference occur on consecutive lines within a short loop body, and Go's map lookup semantics (returning zero value for missing keys) are well-known.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the return value of the map lookup through `Get` (which returns a pointer type) directly to the field access without any intervening nil check.

---

## Vulnerability: Nil Function Pointer Dereference in Dashboard.Render

**CWE:** CWE-476
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L103-L104

### Description
The `Dashboard.Render` method looks up a widget function by name from the `widgets` map. When the name does not exist, the map lookup returns the zero value for `func() string`, which is `nil`. The method then calls `fn()` on the nil function value, causing a nil pointer dereference panic.

### Exploitation Scenario
An attacker runs `./metric-monitor dashboard`. The dashboard mode explicitly calls `dash.Render("nonexistent")`, which looks up a widget name that was never registered. The nil function call triggers a Go runtime panic. In a real application where widget names come from user input or configuration, an attacker can crash the dashboard by requesting any unregistered widget name.

### Remediation Guidance
Check for nil before calling the function:
```go
func (d *Dashboard) Render(name string) string {
    fn, ok := d.widgets[name]
    if !ok || fn == nil {
        return fmt.Sprintf("Widget '%s' not found", name)
    }
    return fn()
}
```

### Complexity Rationale
This is rated Obvious because the map lookup and the nil function call occur on consecutive lines in a two-line method, and the calling code in `main` explicitly passes a nonexistent widget name.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can recognize that a map lookup on `map[string]func() string` returns a potentially nil function value, and the immediate call without a nil check is a direct dereference pattern.

---

## Vulnerability: Nil Pointer Dereference in ingestData via parseMetricLine

**CWE:** CWE-476
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L148-L150

### Description
The `ingestData` function calls `parseMetricLine` for each line of input. When `parseMetricLine` encounters malformed input (fewer than 3 fields, or unparseable values), it returns `nil`. The `ingestData` function then accesses `m.Name`, `m.Value`, `m.Timestamp`, and `m.Tags` without checking for `nil`, causing a nil pointer dereference panic.

### Exploitation Scenario
An attacker runs `./metric-monitor ingest "bad data"`. The `parseMetricLine` function fails to parse the input and returns `nil`. The subsequent `store.Record(m.Name, m.Value, m.Timestamp, m.Tags)` call dereferences the nil pointer when accessing `m.Name`, triggering a panic. An attacker who can supply arbitrary metric data can crash the monitoring application.

### Remediation Guidance
Check the parse result before using it:
```go
func ingestData(store *MetricStore, data string) {
    lines := strings.Split(data, "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        m := parseMetricLine(line)
        if m == nil {
            fmt.Fprintf(os.Stderr, "Failed to parse: %s\n", line)
            continue
        }
        store.Record(m.Name, m.Value, m.Timestamp, m.Tags)
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that `parseMetricLine` has multiple return paths that yield `nil` (three separate `return nil` statements for different parse failures), and the dereference occurs through multiple field accesses passed as function arguments.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to determine that `parseMetricLine` can return `nil`, then trace that return value through the field access expressions in the `store.Record` call.

---

## Vulnerability: Nil Pointer Dereference in compareMetrics

**CWE:** CWE-476
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L153-L157

### Description
The `compareMetrics` function calls `store.Get` for two metric names and dereferences both `m1.Value` and `m2.Value` without nil checks. When either metric name does not exist in the store, `Get` returns `nil`, and the field access causes a nil pointer dereference panic.

### Exploitation Scenario
An attacker runs `./metric-monitor compare cpu_usage nonexistent_metric`. The first `Get("cpu_usage")` succeeds, but `Get("nonexistent_metric")` returns `nil`. The `m2.Value` access in the subtraction triggers a panic. Since metric names come directly from command-line arguments, an attacker has full control over which metrics are compared and can reliably crash the application.

### Remediation Guidance
Validate both pointers before use:
```go
func compareMetrics(store *MetricStore, name1, name2 string) {
    m1 := store.Get(name1)
    m2 := store.Get(name2)
    if m1 == nil || m2 == nil {
        fmt.Fprintf(os.Stderr, "Metric not found\n")
        return
    }
    diff := m1.Value - m2.Value
    fmt.Printf("%s (%.2f) vs %s (%.2f): diff = %.2f\n",
        name1, m1.Value, name2, m2.Value, diff)
}
```

### Complexity Rationale
This is rated Moderate because the function involves two separate nullable pointers from user-controlled input, and both must be validated. The dereferences are embedded in an arithmetic expression and a formatted output statement.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track two separate `Get` return values through the function and recognize that both are dereferenced without nil checks, while also understanding that the metric names originate from user input (`os.Args`).

---

## Vulnerability: Nil Pointer Dereference in Aggregator.Max

**CWE:** CWE-476
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L80-L83

### Description
The `Aggregator.Max` method iterates over metric names and calls `store.Get(name)` for each. The conditional `if best == nil || m.Value > best.Value` checks whether `best` is nil but does not check whether `m` is nil. When a metric name does not exist in the store, `Get` returns `nil`, and `m.Value` in the comparison causes a nil pointer dereference panic. The nil check on `best` creates a false sense of safety that masks the missing nil check on `m`.

### Exploitation Scenario
An attacker runs `./metric-monitor max "nonexistent,cpu_usage"`. If the first name is nonexistent, `Get` returns `nil`, `best` is also `nil`, so the condition evaluates `best == nil` as true and short-circuits — but Go evaluates `m.Value` before the short-circuit in some compilation paths. More reliably, if a valid metric is found first (making `best` non-nil), then a subsequent nonexistent name causes `m.Value` to be evaluated in the `m.Value > best.Value` comparison, triggering the panic. The vulnerability is exploitable whenever any nonexistent metric name appears after a valid one in the list.

### Remediation Guidance
Check for nil on the current metric before comparing:
```go
func (a *Aggregator) Max(names []string) *Metric {
    var best *Metric
    for _, name := range names {
        m := a.store.Get(name)
        if m == nil {
            continue
        }
        if best == nil || m.Value > best.Value {
            best = m
        }
    }
    return best
}
```

### Complexity Rationale
This is rated Nuanced because the conditional expression `best == nil || m.Value > best.Value` contains a nil check on `best` that gives the appearance of null-safety handling. A reviewer must recognize that the nil check is on the wrong variable — `best` is checked but `m` is not — and that the short-circuit evaluation of `||` does not protect against `m` being nil when `best` is non-nil.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools may see the nil check in the conditional and conclude that null safety is handled. The check on `best` satisfies a superficial null-safety analysis, and recognizing that `m` (a different variable) also needs validation requires understanding the semantic relationship between the two pointers in the comparison expression.
