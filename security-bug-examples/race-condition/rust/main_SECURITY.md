# Security Companion Document: main.rs

## Vulnerability: Unsafe Send/Sync Wrapper Bypasses Borrow Checker

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L6-L18  

### Description
The `UnsafeSendCell` struct wraps `UnsafeCell<T>` and manually implements `Send` and `Sync` for all `T`. This bypasses Rust's ownership and borrowing guarantees, allowing shared mutable access to the inner value from multiple threads without any synchronization. Every use of this wrapper throughout the program enables data races that the compiler would otherwise prevent.

### Exploitation Scenario
An attacker identifies that the application uses `unsafe impl Sync` to share mutable state across threads. Any concurrent access through `UnsafeSendCell::get()` produces undefined behavior, which can be exploited for memory corruption, data manipulation, or denial of service.

### Remediation Guidance
Replace `UnsafeSendCell` with `Arc<Mutex<T>>` or `Arc<RwLock<T>>`:
```rust
use std::sync::{Arc, Mutex};

let account = Arc::new(Mutex::new(BankAccount::new("Shared", 10000)));
```

### Complexity Rationale
This is rated Nuanced because the vulnerability is in the type-level safety bypass rather than in any specific operation. A reviewer must understand Rust's `Send`/`Sync` traits and why manually implementing them for `UnsafeCell` is unsound.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools for Rust typically do not audit `unsafe impl Send/Sync` blocks for soundness, and the wrapper appears to be a legitimate low-level abstraction.

---

## Vulnerability: Non-Atomic Balance Update in Bank Simulation

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L39-L53  

### Description
The bank simulation spawns multiple threads that each read the account balance through the unsafe cell, yield, then write back the modified value. The read-modify-write operations on the shared `BankAccount` are not synchronized, causing lost updates and balance corruption.

### Exploitation Scenario
Concurrent threads read the same stale balance and overwrite each other's updates. The final balance diverges from the expected value, enabling financial manipulation in systems that rely on this pattern.

### Remediation Guidance
Use `Arc<Mutex<BankAccount>>` and lock before each operation:
```rust
let acc = Arc::clone(&account);
thread::spawn(move || {
    let mut a = acc.lock().unwrap();
    a.balance += 100;
});
```

### Complexity Rationale
This is rated Obvious because the read-yield-write pattern within `unsafe` blocks on shared data is a textbook data race, immediately visible in the code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the `unsafe` block accessing shared mutable state through a raw pointer with `yield_now()` between read and write is a clear race condition pattern.

---

## Vulnerability: TOCTOU in Ticket Reservation

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L73-L82  

### Description
The ticket simulation checks `tp.available > 0`, yields, then decrements. Multiple threads pass the check simultaneously through the unsafe cell and all decrement, overselling tickets.

### Exploitation Scenario
Concurrent reservation threads all see tickets available before any decrement occurs, resulting in more tickets sold than the actual supply and a negative available count.

### Remediation Guidance
Use `Arc<Mutex<TicketPool>>`:
```rust
let mut pool = p.lock().unwrap();
if pool.available > 0 {
    pool.available -= 1;
    pool.sold += 1;
}
```

### Complexity Rationale
This is rated Obvious because the check-then-act pattern with an explicit yield between check and modification through an unsafe cell is a textbook TOCTOU vulnerability.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of checking a field then decrementing it after a yield within an `unsafe` block is a standard race condition pattern.

---

## Vulnerability: Non-Atomic Shared Counter Increment

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L100-L107  

### Description
The counter simulation reads the shared counter value through the unsafe cell, yields, then writes back the incremented value. Concurrent threads overwrite each other's increments, resulting in a final count far lower than expected.

### Exploitation Scenario
Concurrent counter increments lose updates due to the read-yield-write pattern, exploitable in systems using counters for rate limiting or sequence generation.

### Remediation Guidance
Use `AtomicI64`:
```rust
use std::sync::atomic::{AtomicI64, Ordering};

let counter = Arc::new(AtomicI64::new(0));
counter.fetch_add(1, Ordering::SeqCst);
```

### Complexity Rationale
This is rated Obvious because the read-yield-write pattern on a shared value through an unsafe cell is the most basic form of a data race.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the read-modify-write pattern through `UnsafeCell` with `yield_now()` between operations is a clear race condition.

---

## Vulnerability: Non-Thread-Safe Global Singleton Initialization

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L119-L128  

### Description
The `get_global_config` function checks a `static mut` boolean flag, yields, then initializes a `static mut` `Option<Vec>`. Multiple threads can pass the flag check simultaneously, causing multiple initializations where later ones overwrite the global, losing data written by earlier threads.

### Exploitation Scenario
Multiple threads simultaneously call `get_global_config()`. Each sees `CONFIG_INITIALIZED == false`, creates a new `Vec`, and overwrites the global. Configuration entries pushed by one thread are lost when another thread reinitializes the global.

### Remediation Guidance
Use `std::sync::OnceLock` (Rust 1.70+):
```rust
use std::sync::OnceLock;

static GLOBAL_CONFIG: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();

fn get_global_config() -> &'static Mutex<Vec<(String, String)>> {
    GLOBAL_CONFIG.get_or_init(|| Mutex::new(Vec::new()))
}
```

### Complexity Rationale
This is rated Nuanced because the race condition involves `static mut` variables and requires understanding that `unsafe` access to mutable statics is inherently unsound in multi-threaded contexts. The flag-guarded initialization pattern appears correct at first glance.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools for Rust typically flag `static mut` as a lint warning but do not specifically analyze the initialization race condition pattern or the data loss implications.

---

## Vulnerability: TOCTOU in Inventory Order Processing

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L155-L163  

### Description
The inventory simulation checks stock through the unsafe cell, yields, then decrements. Concurrent order threads read the same stock level and all succeed, driving inventory negative.

### Exploitation Scenario
Multiple concurrent order threads all pass the stock check before any update occurs, resulting in more items sold than available.

### Remediation Guidance
Use `Arc<Mutex<Inventory>>`:
```rust
let mut inv = inv_ref.lock().unwrap();
if inv.stock > 0 {
    inv.stock -= 1;
    inv.orders += 1;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability involves a TOCTOU check through an unsafe cell on a struct with multiple fields, requiring the reviewer to reason about the interaction between stock checks and concurrent modifications.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the TOCTOU pattern through the `UnsafeSendCell` abstraction and correlate the check with the delayed modification.
