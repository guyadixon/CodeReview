# Security Companion Document: main.rs

## Language Exclusion Note: Python, Java, Go, and JavaScript

Python, Java, Go, and JavaScript are excluded from the Out-of-bounds Write (CWE-787) vulnerability class because these languages employ managed memory with automatic bounds checking on array and buffer accesses. Python raises `IndexError` on out-of-range list access, Java throws `ArrayIndexOutOfBoundsException`, Go panics with an index-out-of-range runtime error, and JavaScript returns `undefined` for out-of-bounds array reads and silently extends arrays on writes. None of these languages allow direct memory corruption through out-of-bounds writes because their runtimes enforce memory safety at the language level, making CWE-787 impractical to demonstrate. Rust is included because its `unsafe` blocks allow bypassing the borrow checker and bounds checking, enabling the same class of memory corruption vulnerabilities found in C and C++.

---

## Vulnerability: Off-by-One Out-of-bounds Write in scale_buffer

**CWE:** CWE-787
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L93-L99

### Description
The `scale_buffer` function uses an inclusive range `0..=len` to iterate over the slice elements via raw pointer arithmetic. Since `len` equals `data.len()`, the loop accesses index `len` which is one past the last valid element. The `ptr::read` and `ptr::write` at `ptr.add(len)` read and write one element beyond the allocated slice memory.

### Exploitation Scenario
An attacker runs `./out-of-bounds-write scale "1.0,2.0,3.0" 2.0`. The `scale_buffer` function receives a slice of 3 elements (indices 0, 1, 2) but the loop iterates through index 3 (`0..=3`). The `ptr::write(ptr.add(3), ...)` writes an `f64` value past the end of the Vec's backing allocation, corrupting heap metadata or adjacent allocations. This can lead to heap corruption and potential code execution.

### Remediation Guidance
Use an exclusive range matching the slice length:
```rust
fn scale_buffer(data: &mut [f64], factor: f64) {
    unsafe {
        let ptr = data.as_mut_ptr();
        let len = data.len();
        for i in 0..len {
            let val = ptr::read(ptr.add(i));
            ptr::write(ptr.add(i), val * factor);
        }
    }
}
```
Or better, avoid unsafe entirely:
```rust
fn scale_buffer(data: &mut [f64], factor: f64) {
    for val in data.iter_mut() {
        *val *= factor;
    }
}
```

### Complexity Rationale
This is rated Obvious because the `0..=len` vs `0..len` distinction is a well-known off-by-one pattern in Rust. The inclusive range operator `..=` is visually distinct and a reviewer familiar with Rust will immediately spot the error.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools and Rust linters can flag `0..=len` patterns in unsafe pointer arithmetic as likely off-by-one errors, especially when `len` comes from `.len()` on a slice.

---

## Vulnerability: Unbounded Name Copy in add_item via Unsafe ptr::copy_nonoverlapping

**CWE:** CWE-787
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L33-L39

### Description
The `Inventory::add_item` method copies the input name into a fixed-size 32-byte array using `ptr::copy_nonoverlapping(src, dest, len)` where `len` is `name.len()`. If the name string is longer than 32 bytes, the copy writes past the end of the `names[idx]` array, corrupting adjacent fields in the `Inventory` struct (the `quantities` or `prices` arrays).

### Exploitation Scenario
An attacker runs `./out-of-bounds-write add "a_very_long_item_name_that_exceeds_thirty_two_bytes" 10 5.99`. The `ptr::copy_nonoverlapping` copies all 50+ bytes of the name into the 32-byte slot, overwriting the beginning of the `quantities` array. This corrupts inventory data and could be leveraged for more severe exploitation depending on the memory layout.

### Remediation Guidance
Clamp the copy length to the buffer size:
```rust
unsafe {
    let dest = self.names[idx].as_mut_ptr();
    let src = name.as_ptr();
    let len = name.len().min(31);
    ptr::copy_nonoverlapping(src, dest, len);
    ptr::write_bytes(dest.add(len), 0, 32 - len);
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that `name.len()` is unbounded relative to the 32-byte destination array. The `if len < 32` check on the zero-fill path hints at a size assumption but does not prevent the initial overlong copy.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize that the `len` parameter to `ptr::copy_nonoverlapping` is derived from user input length and is not validated against the destination buffer size, requiring taint analysis through the unsafe block.

---

## Vulnerability: Heap Buffer Overflow via u16 Truncation in merge_strings

**CWE:** CWE-787
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L102-L103

### Description
The `merge_strings` function computes the total string length using a `u16` accumulator: `let total_len: u16 = parts.iter().map(|s| s.len() as u16).sum()`. When the combined length of all input strings exceeds 65535, the `u16` wraps around to a small value. The allocation size `total_len as usize + separator_space` is then too small, but the copy loop writes the full string data, overflowing the heap buffer.

### Exploitation Scenario
An attacker provides many string arguments whose combined length exceeds 65535 bytes. The `u16` sum wraps to a small value (e.g., combined length 65600 wraps to 64). The `alloc` allocates a small buffer, but the loop copies all string data into it, writing far beyond the allocation boundary and corrupting heap memory.

### Remediation Guidance
Use `usize` for the length accumulator:
```rust
let total_len: usize = parts.iter().map(|s| s.len()).sum();
```

### Complexity Rationale
This is rated Nuanced because the vulnerability depends on understanding `u16` overflow semantics in Rust. The `as u16` cast silently truncates, and the wrapping behavior of `u16` sum is not immediately obvious. A reviewer must recognize that the type choice for the accumulator creates an exploitable condition.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must recognize that the `u16` type is insufficient for accumulating arbitrary string lengths, that the `as u16` cast truncates, and that the truncated value flows into an allocation size. This requires integer overflow analysis combined with heap allocation tracking, which most tools do not perform for Rust code.

---

## Vulnerability: Integer Overflow in process_raw_packet Allocation Size

**CWE:** CWE-787
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L140-L152

### Description
The `process_raw_packet` function reads `count` and `elem_size` as `u16` values from untrusted input and computes `alloc_size = (count as usize) * (elem_size as usize)`. While this multiplication cannot overflow on 64-bit systems for `u16` inputs, the function uses `Layout::from_size_align_unchecked` which has undefined behavior if the layout constraints are violated. More critically, the function allocates based on the attacker-controlled `count * elem_size` product but copies `payload.len().min(alloc_size)` bytes. When `alloc_size` is large but the allocation succeeds, the buffer contains uninitialized memory that is implicitly trusted. When `alloc_size` is small due to crafted inputs (e.g., `elem_size=0` is handled, but `elem_size=1` with large `count`), the `min` operation limits the copy but the semantic interpretation of the buffer as `count` elements of `elem_size` bytes is inconsistent with the actual data.

### Exploitation Scenario
An attacker crafts a packet with `count=65535` and `elem_size=1`, producing `alloc_size=65535`. If the payload is shorter, only partial data is copied, but the caller may interpret the buffer as containing 65535 valid elements. On 32-bit systems, `count=65535` and `elem_size=65535` would produce `alloc_size=4,294,836,225` which overflows a 32-bit `usize`, causing a small allocation followed by a large copy.

### Remediation Guidance
Use checked arithmetic and validate the layout:
```rust
let alloc_size = (count as usize).checked_mul(elem_size as usize)
    .filter(|&s| s > 0 && s <= payload.len())
    .unwrap_or(0);
if alloc_size == 0 { return; }
let layout = Layout::from_size_align(alloc_size, 8).unwrap();
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves understanding the interaction between attacker-controlled protocol fields, allocation sizes, and the unsafe `Layout::from_size_align_unchecked` API. The 32-bit overflow scenario requires platform-specific reasoning.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must trace untrusted input through arithmetic operations into `Layout::from_size_align_unchecked` and `alloc`, recognizing that the unchecked layout creation combined with attacker-controlled sizes creates undefined behavior. Most Rust-focused tools do not deeply analyze unsafe allocation patterns.
