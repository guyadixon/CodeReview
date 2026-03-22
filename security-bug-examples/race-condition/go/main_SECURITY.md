# Security Companion Document: main.go

## Vulnerability: Non-Atomic Balance Update in Deposit

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L18-L22  

### Description
The `Deposit` method reads `a.Balance` into a local variable, sleeps, then writes back the incremented value. When multiple goroutines call `Deposit` concurrently, each reads the same stale balance and overwrites the others' updates, causing lost deposits.

### Exploitation Scenario
An attacker triggers concurrent deposit operations. The read-modify-write pattern without synchronization causes some deposits to be silently lost, enabling balance manipulation.

### Remediation Guidance
Use a `sync.Mutex` to protect the balance update:
```go
func (a *BankAccount) Deposit(amount int64) {
    a.mu.Lock()
    defer a.mu.Unlock()
    a.Balance += amount
    a.Log = append(a.Log, fmt.Sprintf("deposit:%d", amount))
}
```

### Complexity Rationale
This is rated Obvious because the read-sleep-write pattern on a shared struct field is a textbook data race immediately visible in the code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because Go's race detector (`go run -race`) and SAST tools can identify unsynchronized access to shared struct fields.

---

## Vulnerability: TOCTOU in Withdraw Balance Check

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L24-L30  

### Description
The `Withdraw` method checks `a.Balance >= amount` and then subtracts after sleeping. Between the check and the subtraction, another goroutine can modify the balance, allowing overdrawing.

### Exploitation Scenario
Concurrent withdrawal requests each pass the balance check before any subtraction occurs, resulting in multiple successful withdrawals that drive the balance negative.

### Remediation Guidance
Protect the check-and-update with a mutex:
```go
func (a *BankAccount) Withdraw(amount int64) bool {
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.Balance >= amount {
        a.Balance -= amount
        return true
    }
    return false
}
```

### Complexity Rationale
This is rated Moderate because the reviewer must understand that the condition check can become stale between the `if` and the balance modification due to goroutine interleaving.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize the TOCTOU pattern where a condition on shared state is followed by a delayed modification.

---

## Vulnerability: Non-Atomic Cross-Account Transfer

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L33-L42  

### Description
The `TransferTo` method checks the source balance, sleeps, then modifies both accounts without synchronization. Concurrent transfers corrupt both balances and violate the conservation invariant.

### Exploitation Scenario
Concurrent transfers between accounts cause money to be created or destroyed due to interleaved unsynchronized reads and writes on two separate struct fields.

### Remediation Guidance
Acquire locks on both accounts in a consistent order:
```go
func (a *BankAccount) TransferTo(other *BankAccount, amount int64) bool {
    // Lock in consistent order to prevent deadlock
    first, second := a, other
    if uintptr(unsafe.Pointer(a)) > uintptr(unsafe.Pointer(other)) {
        first, second = other, a
    }
    first.mu.Lock()
    second.mu.Lock()
    defer first.mu.Unlock()
    defer second.mu.Unlock()
    ...
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability involves two shared structs being modified non-atomically, requiring reasoning about goroutine interleaving across multiple objects.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because detecting this requires analysis to understand that two separate struct fields are modified without a common lock.

---

## Vulnerability: TOCTOU in Ticket Reservation

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L60-L68  

### Description
The `Reserve` method checks `tp.Available > 0`, sleeps, then decrements. Multiple goroutines pass the check simultaneously and all decrement, overselling tickets beyond actual supply.

### Exploitation Scenario
Concurrent reservation requests when few tickets remain all pass the availability check before any decrement, resulting in more tickets sold than available.

### Remediation Guidance
Synchronize the reservation method:
```go
func (tp *TicketPool) Reserve(customer string) int {
    tp.mu.Lock()
    defer tp.mu.Unlock()
    if tp.Available > 0 {
        tp.Available--
        tp.NextID++
        tp.Reservations[tp.NextID] = customer
        return tp.NextID
    }
    return -1
}
```

### Complexity Rationale
This is rated Obvious because the check-then-act pattern with an explicit sleep between check and modification is a textbook TOCTOU vulnerability.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of checking a shared field then decrementing it after a delay is a standard race condition pattern detectable by Go's race detector.

---

## Vulnerability: TOCTOU in Inventory Order Processing

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L91-L99  

### Description
The `PlaceOrder` method reads stock from the map, checks sufficiency, sleeps, then writes back the decremented value. Concurrent orders read the same stock level and all succeed, driving inventory negative.

### Exploitation Scenario
Multiple concurrent order requests for the same product all pass the stock check before any update occurs, resulting in more items sold than available.

### Remediation Guidance
Protect the order processing with a mutex:
```go
func (inv *Inventory) PlaceOrder(name string, qty int) bool {
    inv.mu.Lock()
    defer inv.mu.Unlock()
    stock, ok := inv.Products[name]
    if ok && stock >= qty {
        inv.Products[name] = stock - qty
        inv.OrderCount++
        return true
    }
    return false
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability is embedded within map operations, requiring the reviewer to trace the data flow through the map's read-check-write sequence.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the TOCTOU pattern through map access operations rather than simple field reads.

---

## Vulnerability: Non-Thread-Safe Singleton Config Initialization

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L112-L119  

### Description
The `GetConfig` function checks if `configInstance` is nil, sleeps, then creates a new instance. Multiple goroutines can pass the nil check simultaneously and create separate instances, with later creations overwriting the global pointer and causing data loss.

### Exploitation Scenario
Multiple goroutines simultaneously call `GetConfig()`. Each sees `configInstance == nil`, creates a new object, and overwrites the package-level variable. Settings written by one goroutine are lost when another overwrites the instance.

### Remediation Guidance
Use `sync.Once`:
```go
var configOnce sync.Once

func GetConfig() *ConfigSingleton {
    configOnce.Do(func() {
        configInstance = &ConfigSingleton{
            Settings: make(map[string]string),
        }
    })
    return configInstance
}
```

### Complexity Rationale
This is rated Nuanced because the broken singleton pattern requires understanding Go's memory model and why a simple nil check is insufficient for concurrent initialization.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not flag package-level variable initialization patterns as race conditions, and the idiomatic Go fix (`sync.Once`) is not checked for absence.

---

## Vulnerability: Non-Atomic Shared Counter Increment

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L196-L203  

### Description
The counter simulation reads a shared `int64` variable into a local, sleeps, then writes back the incremented value. Concurrent goroutines overwrite each other's increments, resulting in a final count far lower than expected.

### Exploitation Scenario
An attacker triggers concurrent counter increments. The lost updates cause the counter to undercount, exploitable in systems using counters for rate limiting or resource allocation.

### Remediation Guidance
Use `sync/atomic`:
```go
atomic.AddInt64(&counter, 1)
```

### Complexity Rationale
This is rated Obvious because the read-sleep-write pattern on a shared variable is the most basic form of a data race.

### Detection Difficulty Rationale
This is rated Easily_Detectable because Go's race detector flags unsynchronized read-write access to shared variables, and SAST tools can identify the pattern.
