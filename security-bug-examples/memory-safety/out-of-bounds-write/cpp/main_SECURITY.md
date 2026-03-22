# Security Companion Document: main.cpp

## Language Exclusion Note: Python, Java, Go, and JavaScript

Python, Java, Go, and JavaScript are excluded from the Out-of-bounds Write (CWE-787) vulnerability class because these languages employ managed memory with automatic bounds checking on array and buffer accesses. Python raises `IndexError` on out-of-range list access, Java throws `ArrayIndexOutOfBoundsException`, Go panics with an index-out-of-range runtime error, and JavaScript returns `undefined` for out-of-bounds array reads and silently extends arrays on writes. None of these languages allow direct memory corruption through out-of-bounds writes because their runtimes enforce memory safety at the language level, making CWE-787 impractical to demonstrate.

---

## Vulnerability: Stack Buffer Overflow in set_label via strcpy

**CWE:** CWE-787
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L32-L33

### Description
The `SensorLog::set_label` method copies a user-supplied label into the `Measurement::label` field (48 bytes) using `std::strcpy` without any length validation. If the label string exceeds 47 characters, `strcpy` writes past the end of the `label` array, corrupting adjacent struct members (`reading` and `timestamp`) and potentially the heap metadata of the dynamically allocated `entries_` array.

### Exploitation Scenario
An attacker runs `./sensor-log log 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 25.0` with a label longer than 48 bytes. The `strcpy` overwrites the `reading` and `timestamp` fields of the `Measurement` struct and potentially corrupts adjacent entries in the heap-allocated array, leading to heap corruption.

### Remediation Guidance
Use `std::strncpy` with explicit bounds:
```cpp
void set_label(int index, const char *label) {
    std::strncpy(entries_[index].label, label, sizeof(entries_[index].label) - 1);
    entries_[index].label[sizeof(entries_[index].label) - 1] = '\0';
}
```

### Complexity Rationale
This is rated Obvious because `strcpy` on user input into a fixed-size buffer is a textbook buffer overflow pattern immediately recognizable during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools universally flag `strcpy` calls as dangerous, and the taint flow from `argv` through `add_entry` to `set_label` is direct.

---

## Vulnerability: Heap Buffer Overflow in DataPipeline::ingest Without Capacity Check

**CWE:** CWE-787
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L80-L83

### Description
The `DataPipeline::ingest` method writes incoming data to `buffer_` starting at offset `size_` without checking whether `size_ + count` exceeds `capacity_`. When the total ingested data exceeds the pipeline's capacity, writes go past the end of the heap-allocated buffer, corrupting heap metadata and adjacent allocations.

### Exploitation Scenario
An attacker runs `./sensor-log pipeline "1,2,3,4,5,6,7,8,9,10,11,12"` providing more values than the pipeline capacity (8). The `ingest` method writes 12 doubles starting at `buffer_[0]`, but only 8 slots were allocated. The writes to indices 8-11 corrupt heap memory beyond the allocation.

### Remediation Guidance
Add a capacity check before writing:
```cpp
void ingest(const double *data, int count) {
    int available = capacity_ - size_;
    if (count > available) count = available;
    for (int i = 0; i < count; i++) {
        buffer_[size_ + i] = data[i];
    }
    size_ += count;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding the relationship between the `capacity_` field set in the constructor and the `count` parameter passed to `ingest`. The overflow is not visible from `ingest` alone without knowing the capacity.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the heap allocation size from the constructor through to the write operation in `ingest`, requiring interprocedural analysis of the class state.

---

## Vulnerability: Stack Buffer Overflow in Tagged Input Tag Extraction

**CWE:** CWE-787
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L130-L137

### Description
The `process_tagged_input` function copies the portion of input before the `:` separator into a fixed-size `tag[16]` buffer using `std::memcpy(tag, input, tag_len)`. If the input contains a `:` character at position 16 or later, `tag_len` exceeds the buffer size and the `memcpy` writes past the end of `tag`, corrupting adjacent stack variables including `payload`.

### Exploitation Scenario
An attacker runs `./sensor-log tagged "AAAAAAAAAAAAAAAAAAAAAA:data"` where the tag portion is longer than 16 characters. The `memcpy` writes 22 bytes into `tag[16]`, overflowing into `payload` and other stack variables, potentially enabling stack-based code execution.

### Remediation Guidance
Validate the tag length before copying:
```cpp
if (tag_len >= sizeof(tag)) {
    std::cerr << "Tag too long" << std::endl;
    return;
}
std::memcpy(tag, input, tag_len);
```

### Complexity Rationale
This is rated Moderate because the overflow depends on the position of the `:` separator in user input. A reviewer must trace the `tag_len` computation from `strchr` to understand that it is unbounded relative to the `tag` buffer.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that `tag_len` is derived from pointer arithmetic on user input and is not validated against the destination buffer size before the `memcpy` call.

---

## Vulnerability: Stack Buffer Overflow in Tagged Input Payload via strcpy

**CWE:** CWE-787
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L138

### Description
The `process_tagged_input` function copies the payload portion of the input (everything after `:`) into a fixed-size `payload[256]` buffer using `std::strcpy`. If the payload exceeds 255 characters, `strcpy` writes past the end of the buffer, corrupting the stack frame.

### Exploitation Scenario
An attacker runs `./sensor-log tagged "t:AAAA...AAAA"` with a payload longer than 256 characters. The `strcpy` overflows `payload[256]`, overwriting the return address on the stack and enabling code execution.

### Remediation Guidance
Use `std::strncpy` with bounds:
```cpp
std::strncpy(payload, sep + 1, sizeof(payload) - 1);
payload[sizeof(payload) - 1] = '\0';
```

### Complexity Rationale
This is rated Obvious because `strcpy` on user input into a fixed-size stack buffer is a well-known buffer overflow pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools flag `strcpy` calls with user-controlled source data as a standard dangerous pattern.

---

## Vulnerability: Stack Buffer Overflow in aggregate_readings Without Bounds Check

**CWE:** CWE-787
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L148-L153

### Description
The `aggregate_readings` function declares a fixed-size array `readings[32]` but the parsing loop increments `count` without any upper bound check. When more than 32 comma-separated values are provided, writes to `readings[count]` overflow the stack buffer.

### Exploitation Scenario
An attacker runs `./sensor-log aggregate "1,2,3,...,50"` with more than 32 values. The loop writes past `readings[32]`, corrupting the stack frame and potentially overwriting the return address for code execution.

### Remediation Guidance
Add a bounds check in the loop:
```cpp
while (std::getline(stream, token, ',') && count < 32) {
    readings[count] = std::stod(token);
    count++;
}
```

### Complexity Rationale
This is rated Obvious because the unbounded loop writing into a fixed-size array is visible by inspecting the loop condition and the array declaration.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can detect that the loop has no upper bound matching the array size, a standard array overflow pattern.

---

## Vulnerability: Stack Buffer Overflow in copy_with_prefix Ignoring Destination Size

**CWE:** CWE-787
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L160-L168

### Description
The `copy_with_prefix` function accepts a `dest_size` parameter but never uses it. It computes `needed = prefix_len + src_len + 2`, allocates a temporary buffer of that size, constructs the prefixed string, then copies all `needed` bytes into `dest` via `std::memcpy` regardless of `dest_size`. When the combined prefix and source string exceed the destination buffer size, the write overflows the caller's buffer.

### Exploitation Scenario
An attacker runs `./sensor-log prefix "very_long_prefix_string" "and_a_very_long_source_text_that_together_exceed_64_bytes"` where the combined length exceeds the 64-byte `result` buffer in `main`. The `memcpy` writes past the end of `result`, corrupting the stack frame.

### Remediation Guidance
Use `dest_size` to limit the copy:
```cpp
size_t copy_len = (needed < dest_size) ? needed : dest_size - 1;
std::memcpy(dest, temp, copy_len);
dest[copy_len] = '\0';
```

### Complexity Rationale
This is rated Nuanced because the function signature suggests bounds checking via the `dest_size` parameter, creating a false sense of safety. A reviewer must carefully read the function body to notice that `dest_size` is never referenced, and must trace the caller to understand the actual destination buffer size.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must detect that the `dest_size` parameter is unused and that the `memcpy` size is derived from the input lengths rather than the destination capacity. This requires unused-parameter analysis combined with buffer overflow detection across function boundaries.
