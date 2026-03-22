# Security Companion Document: main.cpp

## Vulnerability: Non-Atomic Balance Update in Deposit

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L20-L24  

### Description
The `deposit` method reads `balance` into a local variable, yields the thread, then writes back the incremented value. When multiple threads call `deposit` concurrently, each reads the same stale balance and overwrites the others' updates, causing lost deposits.

### Exploitation Scenario
An attacker triggers concurrent deposit operations. The read-modify-write pattern without synchronization causes some deposits to be silently lost, enabling balance manipulation.

### Remediation Guidance
Use a `std::mutex` to protect the balance update:
```cpp
void deposit(long amount) {
    std::lock_guard<std::mutex> lock(mu);
    balance += amount;
    log.push_back("deposit:" + std::to_string(amount));
}
```

### Complexity Rationale
This is rated Obvious because the read-yield-write pattern on a shared member variable is a textbook data race immediately visible in the code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of reading a member into a local, yielding, then writing it back without lock protection is a well-known race condition pattern.

---

## Vulnerability: TOCTOU in Withdraw Balance Check

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L26-L32  

### Description
The `withdraw` method checks `balance >= amount` and then subtracts after yielding. Between the check and the subtraction, another thread can modify the balance, allowing overdrawing.

### Exploitation Scenario
Concurrent withdrawal requests each pass the balance check before any subtraction occurs, resulting in multiple successful withdrawals that drive the balance negative.

### Remediation Guidance
Protect the check-and-update with a lock:
```cpp
bool withdraw(long amount) {
    std::lock_guard<std::mutex> lock(mu);
    if (balance >= amount) {
        balance -= amount;
        return true;
    }
    return false;
}
```

### Complexity Rationale
This is rated Moderate because the reviewer must understand that the condition check can become stale between the `if` and the balance modification due to thread interleaving.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize the TOCTOU pattern where a condition on shared state is followed by a delayed modification.

---

## Vulnerability: Non-Atomic Cross-Account Transfer

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L34-L43  

### Description
The `transferTo` method checks the source balance, yields, then modifies both accounts without synchronization. Concurrent transfers corrupt both balances and violate the conservation invariant.

### Exploitation Scenario
Concurrent transfers between accounts cause money to be created or destroyed due to interleaved unsynchronized reads and writes on two separate objects.

### Remediation Guidance
Use `std::scoped_lock` to lock both accounts:
```cpp
bool transferTo(BankAccount &other, long amount) {
    std::scoped_lock lock(mu, other.mu);
    if (balance >= amount) {
        balance -= amount;
        other.balance += amount;
        return true;
    }
    return false;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability involves two shared objects being modified non-atomically, requiring reasoning about interleaving across multiple accounts.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because detecting this requires analysis to understand that two separate object members are modified without a common lock.

---

## Vulnerability: TOCTOU in Ticket Reservation

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L56-L63  

### Description
The `reserve` method checks `available > 0`, yields, then decrements. Multiple threads pass the check simultaneously and all decrement, overselling tickets beyond actual supply.

### Exploitation Scenario
Concurrent reservation requests when few tickets remain all pass the availability check before any decrement, resulting in more tickets sold than available.

### Remediation Guidance
Synchronize the reservation method:
```cpp
int reserve(const std::string &customer) {
    std::lock_guard<std::mutex> lock(mu);
    if (available > 0) {
        available--;
        nextId++;
        reservations[nextId] = customer;
        return nextId;
    }
    return -1;
}
```

### Complexity Rationale
This is rated Obvious because the check-then-act pattern with an explicit yield between check and modification is a textbook TOCTOU vulnerability.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of checking a shared member then decrementing it after a yield is a standard race condition pattern.

---

## Vulnerability: Non-Atomic Shared Counter Increment

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L80-L84  

### Description
The `SharedCounter::increment` method reads `value` into a local, yields, then writes back the incremented value. Concurrent threads overwrite each other's increments, resulting in a final count far lower than expected.

### Exploitation Scenario
Concurrent counter increments lose updates due to the read-yield-write pattern, exploitable in systems using counters for rate limiting or sequence generation.

### Remediation Guidance
Use `std::atomic<long>`:
```cpp
std::atomic<long> value{0};

void increment() {
    value.fetch_add(1);
}
```

### Complexity Rationale
This is rated Obvious because the read-yield-write pattern on a shared member is the most basic form of a data race.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the read-modify-write pattern on a non-atomic member accessed from multiple threads is a standard detection rule.

---

## Vulnerability: TOCTOU in Inventory Order Processing

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L95-L103  

### Description
The `placeOrder` method reads stock from the map, checks sufficiency, yields, then writes back the decremented value. Concurrent orders read the same stock level and all succeed, driving inventory negative.

### Exploitation Scenario
Multiple concurrent order requests for the same product all pass the stock check before any update occurs, resulting in more items sold than available.

### Remediation Guidance
Protect the order processing with a mutex:
```cpp
bool placeOrder(const std::string &name, int qty) {
    std::lock_guard<std::mutex> lock(mu);
    auto it = products.find(name);
    if (it != products.end() && it->second >= qty) {
        products[name] -= qty;
        orderCount++;
        return true;
    }
    return false;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability is embedded within `std::map` operations, requiring the reviewer to trace the data flow through the map's find-check-write sequence.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the TOCTOU pattern through STL container access operations.

---

## Vulnerability: Non-Thread-Safe Lazy Singleton

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L117-L123  

### Description
The `LazyConfig::getInstance()` method checks if the static `instance` pointer is null, yields, then creates a new instance. Multiple threads can pass the null check simultaneously and create separate instances, with later creations overwriting the static pointer and leaking memory.

### Exploitation Scenario
Multiple threads simultaneously call `getInstance()`. Each sees `instance == nullptr`, creates a new object, and overwrites the static pointer. Threads end up with references to different objects, and configuration set by one thread is invisible to others. The overwritten instances are leaked.

### Remediation Guidance
Use C++11 Meyers' singleton (function-local static):
```cpp
static LazyConfig &getInstance() {
    static LazyConfig instance;
    return instance;
}
```

### Complexity Rationale
This is rated Nuanced because the broken singleton pattern requires understanding the C++ memory model and why a simple null check is insufficient. The idiomatic C++11 fix (function-local static) is thread-safe by the standard, but the manual pointer-based approach is not.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not flag manual singleton implementations as race conditions, and the memory leak from overwritten instances adds a secondary vulnerability.
