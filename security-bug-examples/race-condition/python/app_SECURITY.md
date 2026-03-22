# Security Companion Document: app.py

## Vulnerability: Non-Atomic Balance Update in Deposit

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L17-L22  

### Description
The `deposit` method reads `self.balance` into a local variable, sleeps, then writes back the incremented value. When multiple threads call `deposit` concurrently, each thread reads the same stale balance and overwrites the others' updates, causing lost deposits.

### Exploitation Scenario
An attacker triggers many concurrent deposit requests. Due to the read-modify-write pattern without synchronization, some deposits are silently lost, allowing the attacker to manipulate account balances or exploit discrepancies between expected and actual totals.

### Remediation Guidance
Use a `threading.Lock` to protect the balance update:
```python
def deposit(self, amount):
    with self.lock:
        self.balance += amount
        self.transaction_log.append({"type": "deposit", "amount": amount})
```

### Complexity Rationale
This is rated Obvious because the read-modify-write pattern with an explicit `time.sleep` between read and write is a textbook example of a data race, immediately visible in the code.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of reading a shared variable into a local, sleeping, then writing it back is a well-known race condition pattern that SAST tools can identify through data flow analysis.

---

## Vulnerability: TOCTOU in Withdraw Balance Check

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L24-L29  

### Description
The `withdraw` method checks `self.balance >= amount` and then subtracts the amount after a sleep. Between the check and the subtraction, another thread can modify the balance, allowing withdrawals that overdraw the account.

### Exploitation Scenario
An attacker sends concurrent withdrawal requests for the full account balance. Each thread passes the balance check before any subtraction occurs, resulting in multiple successful withdrawals that drive the balance negative.

### Remediation Guidance
Protect the check-and-update with a lock:
```python
def withdraw(self, amount):
    with self.lock:
        if self.balance >= amount:
            self.balance -= amount
            return True
    return False
```

### Complexity Rationale
This is rated Moderate because the check-then-act pattern requires understanding that the condition can become stale between the `if` check and the balance modification.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize the TOCTOU pattern where a condition check on shared state is followed by a delayed modification of that state.

---

## Vulnerability: Non-Atomic Cross-Account Transfer

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L31-L39  

### Description
The `transfer_to` method checks the source balance, sleeps, then decrements the source and increments the destination without any synchronization. Concurrent transfers can corrupt both account balances and violate the conservation invariant (total money in the system).

### Exploitation Scenario
An attacker initiates concurrent transfers between two accounts. The interleaving of unsynchronized reads and writes causes money to be created or destroyed, breaking the total balance invariant and enabling financial manipulation.

### Remediation Guidance
Acquire locks on both accounts in a consistent order to prevent deadlocks:
```python
def transfer_to(self, other, amount):
    first, second = sorted([self, other], key=id)
    with first.lock:
        with second.lock:
            if self.balance >= amount:
                self.balance -= amount
                other.balance += amount
```

### Complexity Rationale
This is rated Moderate because the vulnerability involves two shared objects being modified non-atomically, requiring the reviewer to reason about interleaving across multiple accounts.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because detecting this requires interprocedural analysis to understand that two separate object fields are modified without a common lock.

---

## Vulnerability: TOCTOU in Ticket Reservation

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L49-L55  

### Description
The `reserve` method checks `self.available >= count`, sleeps, then decrements `self.available`. Multiple threads can pass the availability check simultaneously and all decrement the counter, overselling tickets beyond the actual supply.

### Exploitation Scenario
An attacker scripts concurrent reservation requests when only a few tickets remain. All requests pass the availability check before any decrement occurs, resulting in more tickets sold than available — a classic double-spend scenario.

### Remediation Guidance
Use a lock around the check-and-decrement:
```python
def reserve(self, customer, count):
    with self.lock:
        if self.available >= count:
            self.available -= count
            ...
```

### Complexity Rationale
This is rated Obvious because the check-then-act pattern with an explicit sleep between check and modification is a textbook TOCTOU vulnerability.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of checking a shared counter then decrementing it after a delay is a standard race condition pattern recognized by SAST tools.

---

## Vulnerability: TOCTOU in Inventory Order Processing

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L72-L77  

### Description
The `process_order` method checks product stock, sleeps, then decrements it. Concurrent order processing threads can all pass the stock check and decrement the inventory, resulting in negative stock values and overselling.

### Exploitation Scenario
Multiple concurrent order requests for the same product all pass the stock availability check before any decrement occurs. The inventory goes negative, and more items are sold than physically exist.

### Remediation Guidance
Protect the stock check and update with a lock:
```python
def process_order(self, name, quantity):
    with self.lock:
        if name in self.products and self.products[name] >= quantity:
            self.products[name] -= quantity
            self.order_count += 1
```

### Complexity Rationale
This is rated Moderate because the vulnerability is structurally similar to the ticket reservation race but is embedded within a dictionary-based inventory system, requiring the reviewer to trace the data flow through the products dictionary.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the TOCTOU pattern through dictionary access operations rather than simple variable reads.

---

## Vulnerability: Non-Thread-Safe Singleton Initialization

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L88-L97  

### Description
The `ConfigCache` class implements a singleton pattern using `__new__` and `__init__` with a class-level `_initialized` flag. Neither method is synchronized, so concurrent threads can create multiple instances or partially initialize the singleton, leading to lost configuration data or use of an uninitialized object.

### Exploitation Scenario
Multiple threads simultaneously instantiate `ConfigCache`. Due to the race in `__new__`, multiple distinct objects may be created, or one thread's initialization in `__init__` may overwrite settings written by another thread, causing configuration corruption.

### Remediation Guidance
Use a class-level lock for the singleton pattern:
```python
class ConfigCache:
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance
```

### Complexity Rationale
This is rated Nuanced because the race condition spans two dunder methods (`__new__` and `__init__`) and involves class-level state. A reviewer must understand Python's object creation protocol to see the vulnerability.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools rarely model Python's `__new__`/`__init__` interaction for thread safety, and the singleton pattern using class variables is not a standard detection rule.

---

## Vulnerability: File-Based TOCTOU Counter

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L100-L107  

### Description
The `file_based_counter` function reads a counter value from a file, increments it in memory, and writes it back. Without file locking, concurrent threads read the same value and overwrite each other's increments, resulting in a final count far lower than expected.

### Exploitation Scenario
An attacker triggers concurrent requests that each call `file_based_counter`. The file-based TOCTOU allows the counter to lose increments, which could be exploited in systems using file-based counters for rate limiting, sequence generation, or resource allocation.

### Remediation Guidance
Use file locking with `fcntl.flock`:
```python
import fcntl

def file_based_counter(filepath):
    with open(filepath, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        count = int(f.read().strip() or "0") + 1
        f.seek(0)
        f.write(str(count))
        f.truncate()
        fcntl.flock(f, fcntl.LOCK_UN)
    return count
```

### Complexity Rationale
This is rated Nuanced because the race condition involves filesystem I/O rather than in-memory shared state. The vulnerability requires understanding that file operations are not atomic across threads or processes.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not model file I/O operations as shared resources subject to race conditions, and the read-then-write pattern across separate `open` calls is not a standard detection rule.
