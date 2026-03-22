# Security Companion Document: main.c

## Language Exclusion Note: Python, Java, Go, and JavaScript

Python, Java, Go, and JavaScript are excluded from the Out-of-bounds Write (CWE-787) vulnerability class because these languages employ managed memory with automatic bounds checking on array and buffer accesses. Python raises `IndexError` on out-of-range list access, Java throws `ArrayIndexOutOfBoundsException`, Go panics with an index-out-of-range runtime error, and JavaScript returns `undefined` for out-of-bounds array reads and silently extends arrays on writes. None of these languages allow direct memory corruption through out-of-bounds writes because their runtimes enforce memory safety at the language level, making CWE-787 impractical to demonstrate.

---

## Vulnerability: Stack Buffer Overflow in Name Import via strcpy

**CWE:** CWE-787
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L33-L34

### Description
The `import_name` function copies user-supplied input into a fixed-size stack buffer `staging[NAME_LEN]` (32 bytes) using `strcpy`, which performs no bounds checking. If the input string exceeds 31 characters, `strcpy` writes past the end of `staging`, corrupting adjacent stack memory including the saved return address.

### Exploitation Scenario
An attacker runs `./record-store add AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1.0` with a name longer than 32 bytes. The `strcpy` call overwrites the stack frame of `import_name`, potentially overwriting the return address. A crafted payload can redirect execution to attacker-controlled code.

### Remediation Guidance
Use `strncpy` with explicit bounds:
```c
static void import_name(Record *rec, const char *input) {
    strncpy(rec->name, input, NAME_LEN - 1);
    rec->name[NAME_LEN - 1] = '\0';
}
```

### Complexity Rationale
This is rated Obvious because `strcpy` on user input into a fixed-size buffer is a textbook buffer overflow pattern immediately recognizable during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools universally flag `strcpy` calls as dangerous, and taint analysis from `argv` to `strcpy` is straightforward.

---

## Vulnerability: Stack Buffer Overflow in CSV Value Processing

**CWE:** CWE-787
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L137-L143

### Description
The `process_value_list` function declares a fixed-size array `values[64]` but the parsing loop allows `count` to reach up to 256 before stopping. When more than 64 comma-separated values are provided, the writes to `values[count++]` overflow the stack buffer, corrupting adjacent stack memory.

### Exploitation Scenario
An attacker runs `./record-store values "1,2,3,...,100"` with more than 64 comma-separated numbers. The loop writes past `values[64]`, overwriting the stack frame. With a carefully crafted input, the attacker can overwrite the return address and gain control of execution.

### Remediation Guidance
Match the loop bound to the array size:
```c
while (tok && count < 64) {
    values[count++] = atof(tok);
    tok = strtok(NULL, ",");
}
```

### Complexity Rationale
This is rated Obvious because the mismatch between the array size (64) and the loop bound (256) is visible by comparing two adjacent lines of code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can compare the declared array size against the loop termination condition and flag the mismatch.

---

## Vulnerability: Stack Buffer Overflow in apply_transform Workspace

**CWE:** CWE-787
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L118-L122

### Description
The `apply_transform` function uses a fixed-size stack array `workspace[128]` but accepts an arbitrary `count` parameter. When called from `process_value_list`, `count` can be up to 256 (the loop bound in the caller). Writing to `workspace[i]` for `i >= 128` overflows the stack buffer.

### Exploitation Scenario
An attacker provides more than 128 comma-separated values via the `values` command. The `process_value_list` function passes the oversized array to `apply_transform`, which writes past `workspace[128]`. The overflow corrupts the stack frame and can be leveraged for code execution.

### Remediation Guidance
Add a bounds check or use dynamic allocation:
```c
static void apply_transform(double *values, int count, double factor) {
    for (int i = 0; i < count; i++) {
        values[i] = values[i] * factor;
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires tracing the `count` parameter from the caller (`process_value_list`) to understand that it can exceed the `workspace` array size. The overflow is not visible from `apply_transform` alone.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to determine that the `count` argument can exceed 128, requiring taint tracking from the caller through the function parameter.

---

## Vulnerability: Heap Buffer Overflow via Integer Wraparound in merge_fields

**CWE:** CWE-787
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L53-L57

### Description
The `merge_fields` function computes the total allocation size using a `uint32_t` accumulator. When many large fields are provided, the sum can wrap around to a small value due to 32-bit unsigned integer overflow. The subsequent `malloc(total)` allocates a small buffer, but the copy loop writes the full field data, overflowing the heap buffer.

### Exploitation Scenario
An attacker provides command-line arguments with field strings whose combined length exceeds 4 GB (or more practically, fields that cause the `uint32_t` sum to wrap to a small value). The `malloc` allocates a small buffer, and the `memcpy` loop writes far beyond the allocation, enabling heap corruption and potential code execution.

### Remediation Guidance
Use `size_t` for the accumulator and validate against a maximum:
```c
size_t total = 0;
for (int i = 0; i < num_fields; i++) {
    total += strlen(fields[i]) + 1;
    if (total > MAX_MERGE_SIZE) return NULL;
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability depends on understanding unsigned integer wraparound behavior and recognizing that `uint32_t` is insufficient for accumulating arbitrary string lengths. The overflow is not apparent from a casual reading.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must recognize that the `uint32_t` accumulator can wrap around and that the wrapped value is used as a `malloc` size, requiring integer overflow analysis combined with heap allocation tracking.

---

## Vulnerability: Heap Buffer Overflow via Untrusted Entry Count in batch_import

**CWE:** CWE-787
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L85-L90

### Description
The `batch_import` function reads `entry_count` directly from untrusted input data as a `uint16_t` and uses it to compute the allocation size `entry_count * sizeof(Record)`. While `uint16_t` limits the maximum to 65535, the multiplication `entry_count * sizeof(Record)` is performed in `size_t` arithmetic. The allocated buffer is sized for `entry_count` records, but the copy loop reads from the input data which may be shorter than expected, leaving uninitialized data. More critically, the second loop copies up to `entry_count` records into `store.entries` without validating that `entry_count` is consistent with the actual data provided, and the first loop's `remaining` check can be bypassed when the data is crafted to have a large `entry_count` with minimal payload.

### Exploitation Scenario
An attacker crafts binary input where the first two bytes encode a large `entry_count` (e.g., 65535) but the actual payload is small. The `malloc` allocates a large buffer, but the copy loop reads from `batch[i]` entries that were never fully initialized from the input (the inner loop breaks early due to insufficient `remaining`). The second loop then copies these partially-initialized records into the global `store`, potentially leaking stack/heap data or causing undefined behavior when the uninitialized fields are accessed.

### Remediation Guidance
Validate that the input data is large enough for the declared entry count:
```c
size_t needed = (size_t)entry_count * (sizeof(int) + NAME_LEN);
if (needed > (size_t)(data_len - sizeof(uint16_t))) {
    free(batch);
    return;
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves parsing a binary protocol with an attacker-controlled count field, requiring understanding of the relationship between the declared count, the actual data length, and the allocation size. The partial initialization issue is subtle.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must trace the untrusted `entry_count` from `memcpy` through the allocation size calculation and into the loop bounds, recognizing that the data length validation is insufficient to prevent reading uninitialized heap memory.

---

## Vulnerability: Stack Buffer Overflow in copy_record_names Without Bounds Check

**CWE:** CWE-787
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L148-L155

### Description
The `copy_record_names` function accepts a `dest_size` parameter but never uses it to limit writes. The function iterates over all records, copying each name and a newline character into `dest` without checking whether `offset` exceeds `dest_size`. When the total length of all record names exceeds the destination buffer size, the writes overflow the buffer.

### Exploitation Scenario
An attacker adds many records with long names (up to 31 characters each). When the `names` command is executed, `copy_record_names` is called with a 256-byte buffer. If the combined name data exceeds 256 bytes, the function writes past the end of `name_buf` on the stack, corrupting the caller's stack frame.

### Remediation Guidance
Check bounds before each write:
```c
static void copy_record_names(char *dest, size_t dest_size) {
    size_t offset = 0;
    for (int i = 0; i < store.count; i++) {
        size_t name_len = strlen(store.entries[i].name);
        if (offset + name_len + 2 > dest_size) break;
        memcpy(dest + offset, store.entries[i].name, name_len);
        offset += name_len;
        dest[offset] = '\n';
        offset++;
    }
    dest[offset] = '\0';
}
```

### Complexity Rationale
This is rated Moderate because the function signature suggests bounds checking via the `dest_size` parameter, but a reviewer must notice that the parameter is accepted but never referenced in the function body.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to detect that the `dest_size` parameter is unused and that the `memcpy` writes are unbounded relative to the destination buffer, requiring unused-parameter analysis combined with buffer overflow detection.
