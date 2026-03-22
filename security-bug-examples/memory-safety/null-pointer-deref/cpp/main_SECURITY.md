# Security Companion Document: main.cpp

## Language Exclusion Note: Python, JavaScript, and Rust

Python and JavaScript are excluded from the NULL Pointer Dereference (CWE-476) vulnerability class because these languages do not expose raw pointers. In Python, accessing an attribute on `None` raises an `AttributeError` exception that can be caught and handled, preventing undefined behavior or memory corruption. Similarly, in JavaScript, accessing a property on `null` or `undefined` raises a `TypeError` exception. While these exceptions can cause application crashes if unhandled, they do not produce the memory-safety consequences (segmentation faults, undefined behavior, potential code execution) that characterize CWE-476 in languages with raw pointers.

Rust is excluded because its type system prevents null pointer dereferences at compile time. Rust has no null value for references; instead, it uses the `Option<T>` enum to represent values that may or may not exist. The compiler forces the programmer to handle the `None` case before accessing the inner value, making it impossible to dereference a null pointer in safe Rust code. While `unsafe` blocks can create raw pointers, idiomatic Rust code avoids this pattern entirely.

---

## Vulnerability: NULL Pointer Dereference in AlertEngine::evaluate

**CWE:** CWE-476
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L99-L100

### Description
The `AlertEngine::evaluate` method iterates over alert rules and calls `registry.get_latest(rule.sensor_id)` for each rule. When a rule references a sensor ID that has no recorded reading (e.g., sensor ID 6), `get_latest` returns `nullptr`. The method then dereferences `reading->value` without checking for `nullptr`, causing a segmentation fault.

### Exploitation Scenario
An attacker runs `./sensor-monitor alert`. The alert engine has a rule for sensor ID 6, which was never registered or recorded. The `get_latest(6)` call returns `nullptr`, and `reading->value` dereferences the null pointer. This crashes the monitoring application, causing a denial-of-service. In a long-running sensor monitoring system, this crash could cause missed alerts for legitimate sensor threshold violations.

### Remediation Guidance
Check the return value before dereferencing:
```cpp
void evaluate(SensorRegistry &registry) {
    for (auto &rule : rules_) {
        SensorReading *reading = registry.get_latest(rule.sensor_id);
        if (!reading) {
            std::cerr << "No reading for sensor " << rule.sensor_id << std::endl;
            continue;
        }
        double val = reading->value;
        std::string name = registry.get_name(rule.sensor_id);
        // ... threshold checks
    }
}
```

### Complexity Rationale
This is rated Obvious because the `get_latest` call and the unchecked dereference occur on consecutive lines, and the alert setup in `main` explicitly adds a rule for sensor ID 6 which has no corresponding data.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the return value of `get_latest` (which has an explicit `return nullptr` path) directly to the dereference on the next line.

---

## Vulnerability: NULL Pointer Dereference in find_max_reading

**CWE:** CWE-476
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L115-L118

### Description
The `find_max_reading` function iterates over a list of sensor IDs and calls `registry.get_latest(id)` for each. When an ID has no recorded reading (e.g., ID 99 which is pushed into the list in `main`), `get_latest` returns `nullptr`. The function then dereferences `r->value` in the comparison without checking for `nullptr`.

### Exploitation Scenario
An attacker runs `./sensor-monitor max`. The code appends sensor ID 99 to the list before calling `find_max_reading`. Since sensor 99 has no reading, `get_latest(99)` returns `nullptr`, and `r->value` causes a segmentation fault. An attacker who can influence the sensor ID list (e.g., through a configuration file or command-line argument) can reliably crash the application.

### Remediation Guidance
Skip null readings in the comparison:
```cpp
static SensorReading *find_max_reading(SensorRegistry &registry,
                                        const std::vector<int> &ids) {
    SensorReading *max_reading = nullptr;
    for (int id : ids) {
        SensorReading *r = registry.get_latest(id);
        if (!r) continue;
        if (!max_reading || r->value > max_reading->value) {
            max_reading = r;
        }
    }
    return max_reading;
}
```

### Complexity Rationale
This is rated Obvious because the `get_latest` return value is immediately used in a comparison without a NULL check, and the calling code in `main` explicitly includes a nonexistent sensor ID.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the data flow from `get_latest` (nullable return) to the pointer dereference is direct and within the same loop body.

---

## Vulnerability: NULL Pointer Dereference in ingest_readings via parse_reading

**CWE:** CWE-476
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L137-L140

### Description
The `ingest_readings` function calls `parse_reading` for each line of input data. When `parse_reading` fails to parse a line (e.g., malformed input), it returns `nullptr`. The `ingest_readings` function then dereferences `parsed->sensor_id`, `parsed->value`, `parsed->timestamp`, and `parsed->unit` without checking for `nullptr`.

### Exploitation Scenario
An attacker runs `./sensor-monitor ingest "bad data"`. The `parse_reading` function fails to parse the malformed input and returns `nullptr`. The subsequent `registry.record(parsed->sensor_id, ...)` call dereferences the null pointer, causing a segmentation fault. An attacker who can supply arbitrary input data to the ingest command can reliably crash the monitoring application.

### Remediation Guidance
Check the parse result before using it:
```cpp
static void ingest_readings(SensorRegistry &registry, const std::string &data) {
    std::istringstream stream(data);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        SensorReading *parsed = parse_reading(line);
        if (!parsed) {
            std::cerr << "Failed to parse: " << line << std::endl;
            continue;
        }
        registry.record(parsed->sensor_id, parsed->value,
                       parsed->timestamp, parsed->unit);
        delete parsed;
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that `parse_reading` can return `nullptr` on malformed input (an interprocedural analysis), and the dereference occurs through multiple field accesses passed as function arguments.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to analyze `parse_reading` to determine it can return `nullptr`, then trace that return value through the function argument expressions in the `registry.record` call.

---

## Vulnerability: NULL Pointer Dereference in compare_sensors

**CWE:** CWE-476
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L155-L161

### Description
The `compare_sensors` function takes two user-supplied sensor IDs, calls `registry.get_latest` for each, and dereferences both `r1->value` and `r2->value` without NULL checks. When either sensor ID does not have a recorded reading, `get_latest` returns `nullptr`, and the dereference causes a segmentation fault.

### Exploitation Scenario
An attacker runs `./sensor-monitor compare 1 999`. The first `get_latest(1)` succeeds, but `get_latest(999)` returns `nullptr` because sensor 999 does not exist. The `r2->value` dereference in the subtraction causes a segmentation fault. Since the sensor IDs come directly from command-line arguments, an attacker has full control over which IDs are compared and can reliably trigger the crash.

### Remediation Guidance
Validate both pointers before use:
```cpp
static void compare_sensors(SensorRegistry &registry, int id1, int id2) {
    SensorReading *r1 = registry.get_latest(id1);
    SensorReading *r2 = registry.get_latest(id2);
    if (!r1 || !r2) {
        std::cerr << "Sensor reading not found" << std::endl;
        return;
    }
    double diff = r1->value - r2->value;
    std::cout << "Sensor " << id1 << " vs " << id2 << ": difference = "
              << diff << " " << r1->unit << std::endl;
}
```

### Complexity Rationale
This is rated Moderate because the function involves two separate nullable pointers from user-controlled input, and both must be validated. The dereferences are embedded in an arithmetic expression and output statement rather than being simple field accesses.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track two separate `get_latest` return values through the function and recognize that both are dereferenced without NULL checks, while also understanding that the sensor IDs come from user input (`argv`).

---

## Vulnerability: NULL Pointer Dereference in compute_average with Division by Zero

**CWE:** CWE-476
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L145-L152

### Description
The `compute_average` function iterates over sensor IDs and correctly checks `if (r)` before accumulating values, which appears to handle the NULL case. However, when called from `main` with the list `{1, 2, 3, 4, 5, 10}`, sensor ID 10 does not exist, so `get_latest(10)` returns `nullptr` and is skipped. The subtle issue is that if all sensor IDs in the list are invalid, `count` remains 0, and the division `sum / count` produces a floating-point division by zero. While this function does check for NULL pointers individually, the missing validation of `count > 0` before division represents a related null-safety gap where the absence of valid data is not properly handled.

### Exploitation Scenario
An attacker who can influence the sensor ID list (e.g., through a configuration file or extended CLI interface) provides only nonexistent sensor IDs. All `get_latest` calls return `nullptr`, `count` stays at 0, and `sum / count` produces `inf` or `nan` depending on the platform. While floating-point division by zero does not crash on most platforms, the resulting `inf` or `nan` value propagates through downstream calculations, potentially corrupting monitoring thresholds, triggering false alerts, or masking genuine sensor anomalies.

### Remediation Guidance
Check that at least one valid reading was found before dividing:
```cpp
static void compute_average(SensorRegistry &registry,
                            const std::vector<int> &ids) {
    double sum = 0.0;
    int count = 0;
    for (int id : ids) {
        SensorReading *r = registry.get_latest(id);
        if (r) {
            sum += r->value;
            count++;
        }
    }
    if (count == 0) {
        std::cout << "No valid sensor readings found" << std::endl;
        return;
    }
    std::cout << "Average across " << count << " sensors: "
              << (sum / count) << std::endl;
}
```

### Complexity Rationale
This is rated Nuanced because the function appears to handle NULL pointers correctly with the `if (r)` check, which gives a false sense of safety. The actual vulnerability is the missing guard on `count` before division, which is a second-order consequence of the NULL returns. A reviewer must reason about the aggregate effect of multiple NULL returns rather than a single missing check.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically focus on direct NULL pointer dereferences and are unlikely to flag a division-by-zero that results from all nullable returns being NULL. The NULL check on `r` satisfies most tools' null-safety analysis, masking the downstream division issue.
