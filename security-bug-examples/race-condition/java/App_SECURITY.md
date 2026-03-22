# Security Companion Document: App.java

## Vulnerability: Non-Atomic Balance Update in Deposit

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L23-L27  

### Description
The `deposit` method reads `balance` into a local variable, yields the thread, then writes back the incremented value. When multiple threads call `deposit` concurrently, each reads the same stale balance and overwrites the others' updates, causing lost deposits.

### Exploitation Scenario
An attacker triggers concurrent deposit operations. Due to the read-modify-write pattern without synchronization, some deposits are silently lost, allowing manipulation of account balances.

### Remediation Guidance
Use `synchronized` or `AtomicLong`:
```java
synchronized void deposit(long amount) {
    balance += amount;
    log.add("deposit:" + amount);
}
```

### Complexity Rationale
This is rated Obvious because the read-modify-write pattern with an explicit `Thread.yield()` between read and write is a textbook data race.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of reading a field into a local, yielding, then writing it back is a well-known race condition pattern that SAST tools can identify.

---

## Vulnerability: TOCTOU in Withdraw Balance Check

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L29-L35  

### Description
The `withdraw` method checks `balance >= amount` and then subtracts after yielding. Between the check and the subtraction, another thread can modify the balance, allowing withdrawals that overdraw the account.

### Exploitation Scenario
Concurrent withdrawal requests each pass the balance check before any subtraction occurs, resulting in multiple successful withdrawals that drive the balance negative.

### Remediation Guidance
Synchronize the check-and-update:
```java
synchronized boolean withdraw(long amount) {
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
**Affected Lines:** L37-L45  

### Description
The `transferTo` method checks the source balance, yields, then modifies both accounts without synchronization. Concurrent transfers corrupt both balances and violate the conservation invariant.

### Exploitation Scenario
Concurrent transfers between accounts cause money to be created or destroyed due to interleaved unsynchronized reads and writes, breaking the total balance invariant.

### Remediation Guidance
Synchronize on both accounts in a consistent order:
```java
boolean transferTo(BankAccount other, long amount) {
    BankAccount first = System.identityHashCode(this) < System.identityHashCode(other) ? this : other;
    BankAccount second = first == this ? other : this;
    synchronized (first) {
        synchronized (second) {
            if (this.balance >= amount) {
                this.balance -= amount;
                other.balance += amount;
                return true;
            }
        }
    }
    return false;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability involves two shared objects being modified non-atomically, requiring reasoning about interleaving across multiple accounts.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because detecting this requires interprocedural analysis to understand that two separate object fields are modified without a common lock.

---

## Vulnerability: TOCTOU in Ticket Reservation

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L60-L68  

### Description
The `reserve` method checks `available > 0`, yields, then decrements. Multiple threads pass the check simultaneously and all decrement, overselling tickets beyond actual supply.

### Exploitation Scenario
Concurrent reservation requests when few tickets remain all pass the availability check before any decrement, resulting in more tickets sold than available.

### Remediation Guidance
Synchronize the reservation method:
```java
synchronized int reserve(String customer) {
    if (available > 0) {
        available--;
        nextId++;
        reservations.put(nextId, customer);
        return nextId;
    }
    return -1;
}
```

### Complexity Rationale
This is rated Obvious because the check-then-act pattern with an explicit yield between check and modification is a textbook TOCTOU vulnerability.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of checking a shared counter then decrementing it after a yield is a standard race condition pattern.

---

## Vulnerability: Non-Thread-Safe Lazy Singleton

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L93-L100  

### Description
The `LazyConfig.getInstance()` method checks if `instance` is null, yields, then creates a new instance. Multiple threads can pass the null check simultaneously and create separate instances, violating the singleton guarantee and causing configuration data loss.

### Exploitation Scenario
Multiple threads simultaneously call `getInstance()`. Each sees `instance == null`, creates a new object, and overwrites the static field. Threads end up with references to different objects, and configuration set by one thread is invisible to others.

### Remediation Guidance
Use double-checked locking with `volatile`, or use an enum singleton:
```java
private static volatile LazyConfig instance;

static LazyConfig getInstance() {
    if (instance == null) {
        synchronized (LazyConfig.class) {
            if (instance == null) {
                instance = new LazyConfig();
            }
        }
    }
    return instance;
}
```

### Complexity Rationale
This is rated Nuanced because the broken singleton pattern is a well-known Java concurrency pitfall, but recognizing it requires understanding the Java Memory Model and why the naive check-then-create is insufficient.

### Detection Difficulty Rationale
This is rated Likely_Missed because while some SAST tools have rules for non-thread-safe singletons, many do not flag this pattern, especially when the field is not `volatile`.

---

## Vulnerability: Non-Atomic Shared Counter Increment

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L107-L111  

### Description
The `SharedCounter.increment()` method reads `value` into a local, yields, then writes back the incremented value. Concurrent threads overwrite each other's increments, resulting in a final count far lower than expected.

### Exploitation Scenario
An attacker triggers concurrent counter increments. The lost updates cause the counter to undercount, which could be exploited in systems using counters for rate limiting or resource allocation.

### Remediation Guidance
Use `AtomicLong`:
```java
private AtomicLong value = new AtomicLong(0);

void increment() {
    value.incrementAndGet();
}
```

### Complexity Rationale
This is rated Obvious because the read-yield-write pattern on a shared field is the most basic form of a data race.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the read-modify-write pattern on a non-volatile, non-atomic field accessed from multiple threads is a standard SAST detection rule.

---

## Vulnerability: TOCTOU in Order Processing Inventory Check

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L119-L126  

### Description
The `placeOrder` method reads stock from the map, checks sufficiency, yields, then writes back the decremented value. Concurrent orders read the same stock level and all succeed, driving inventory negative.

### Exploitation Scenario
Multiple concurrent order requests for the same product all pass the stock check before any update occurs, resulting in more items sold than available.

### Remediation Guidance
Synchronize the order processing:
```java
synchronized boolean placeOrder(String product, int qty) {
    Integer stock = inventory.get(product);
    if (stock != null && stock >= qty) {
        inventory.put(product, stock - qty);
        orderCount++;
        return true;
    }
    return false;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability is embedded within HashMap operations, requiring the reviewer to trace the data flow through the map's get-check-put sequence.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the TOCTOU pattern through HashMap access operations rather than simple field reads.
