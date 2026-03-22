# Security Companion Document: app.js

## Vulnerability: Non-Atomic Balance Update in Deposit

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L12-L17  

### Description
The `deposit` method reads `this.balance` into a local variable, awaits `setImmediate` (yielding the event loop), then writes back the incremented value. When multiple async tasks call `deposit` concurrently via `Promise.all`, each reads the same stale balance and overwrites the others' updates, causing lost deposits.

### Exploitation Scenario
An attacker triggers concurrent deposit operations through async task scheduling. The read-await-write pattern causes some deposits to be silently lost, enabling balance manipulation.

### Remediation Guidance
Use an async mutex or serialize access:
```javascript
const { Mutex } = require('async-mutex');
const mutex = new Mutex();

async deposit(amount) {
    const release = await mutex.acquire();
    try {
        this.balance += amount;
        this.log.push({ type: "deposit", amount });
    } finally {
        release();
    }
}
```

### Complexity Rationale
This is rated Moderate because the race condition occurs through async/await interleaving rather than traditional threading. A reviewer must understand that `await` yields the event loop and allows other async tasks to execute.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to understand that `await` in a `Promise.all` context creates interleaving opportunities, which is a less common detection pattern than thread-based races.

---

## Vulnerability: TOCTOU in Withdraw Balance Check

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L19-L26  

### Description
The `withdraw` method checks `this.balance >= amount`, awaits (yielding the event loop), then subtracts. Between the check and the subtraction, another async task can modify the balance, allowing overdrawing.

### Exploitation Scenario
Concurrent async withdrawal tasks each pass the balance check before any subtraction occurs, resulting in multiple successful withdrawals that drive the balance negative.

### Remediation Guidance
Use an async mutex to serialize the check-and-update:
```javascript
async withdraw(amount) {
    const release = await mutex.acquire();
    try {
        if (this.balance >= amount) {
            this.balance -= amount;
            return true;
        }
        return false;
    } finally {
        release();
    }
}
```

### Complexity Rationale
This is rated Moderate because the reviewer must understand that the `await` between the check and the modification creates a window for other async tasks to interleave.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize the async TOCTOU pattern where a condition check is separated from its modification by an `await`.

---

## Vulnerability: Non-Atomic Cross-Account Transfer

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L28-L37  

### Description
The `transferTo` method checks the source balance, awaits, then modifies both accounts without serialization. Concurrent async transfers corrupt both balances and violate the conservation invariant.

### Exploitation Scenario
Concurrent async transfers between accounts cause money to be created or destroyed due to interleaved reads and writes across the `await` boundary.

### Remediation Guidance
Serialize transfers with an async mutex covering both accounts:
```javascript
async transferTo(other, amount) {
    const release = await mutex.acquire();
    try {
        if (this.balance >= amount) {
            this.balance -= amount;
            other.balance += amount;
            return true;
        }
        return false;
    } finally {
        release();
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability involves two objects being modified non-atomically across an `await` boundary, requiring reasoning about async interleaving across multiple objects.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because detecting this requires understanding that two separate object properties are modified across an `await` without serialization.

---

## Vulnerability: TOCTOU in Ticket Reservation

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L48-L56  

### Description
The `reserve` method checks `this.available > 0`, awaits, then decrements. Multiple async tasks pass the check simultaneously and all decrement, overselling tickets beyond actual supply.

### Exploitation Scenario
Concurrent async reservation tasks when few tickets remain all pass the availability check before any decrement, resulting in more tickets sold than available.

### Remediation Guidance
Serialize the reservation with an async mutex:
```javascript
async reserve(customer) {
    const release = await mutex.acquire();
    try {
        if (this.available > 0) {
            this.available--;
            this.nextId++;
            this.reservations[this.nextId] = customer;
            return this.nextId;
        }
        return null;
    } finally {
        release();
    }
}
```

### Complexity Rationale
This is rated Obvious because the check-then-act pattern with an explicit `await` between check and modification is a clear TOCTOU vulnerability.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of checking a property, awaiting, then decrementing is a straightforward async race condition pattern.

---

## Vulnerability: TOCTOU in Inventory Order Processing

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L82-L90  

### Description
The `placeOrder` method reads stock from the products object, awaits, then writes back the decremented value. Concurrent async orders read the same stock level and all succeed, driving inventory negative.

### Exploitation Scenario
Multiple concurrent async order tasks for the same product all pass the stock check before any update occurs, resulting in more items sold than available.

### Remediation Guidance
Serialize order processing with an async mutex:
```javascript
async placeOrder(name, qty) {
    const release = await mutex.acquire();
    try {
        if (this.products[name] >= qty) {
            this.products[name] -= qty;
            this.orderCount++;
            return true;
        }
        return false;
    } finally {
        release();
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability is embedded within object property access, requiring the reviewer to trace the data flow through the products object across the `await` boundary.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the async TOCTOU pattern through object property access operations.

---

## Vulnerability: Non-Thread-Safe Async Singleton

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L103-L109  

### Description
The `getConfig` function checks if `configInstance` is null, awaits (yielding the event loop), then creates a new instance. Multiple async tasks can pass the null check simultaneously and create separate instances, with later creations overwriting the module-level variable.

### Exploitation Scenario
Multiple async tasks simultaneously call `getConfig()`. Each sees `configInstance === null`, creates a new object, and overwrites the module-level variable. Settings written by one task are lost when another task overwrites the instance.

### Remediation Guidance
Use a cached promise to ensure single initialization:
```javascript
let configPromise = null;

async function getConfig() {
    if (!configPromise) {
        configPromise = (async () => {
            return { settings: {} };
        })();
    }
    return configPromise;
}
```

### Complexity Rationale
This is rated Nuanced because the race condition occurs through async/await interleaving in a singleton pattern. A reviewer must understand that the `await` between the null check and the assignment creates a window for concurrent initialization.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not model async singleton initialization patterns as race conditions, and the JavaScript event loop concurrency model is less commonly analyzed for races than thread-based models.

---

## Vulnerability: File-Based TOCTOU Counter

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L111-L118  

### Description
The `fileBasedCounter` function reads a counter value from a file using `readFileSync`, increments it in memory, and writes it back with `writeFileSync`. Without file locking, concurrent async tasks (or worker threads) read the same value and overwrite each other's increments, resulting in a final count lower than expected.

### Exploitation Scenario
An attacker triggers concurrent requests that each call `fileBasedCounter`. The file-based TOCTOU allows the counter to lose increments, exploitable in systems using file-based counters for rate limiting, sequence generation, or resource allocation.

### Remediation Guidance
Use a file locking library such as `proper-lockfile`:
```javascript
const lockfile = require('proper-lockfile');

function fileBasedCounter(filepath) {
    const release = lockfile.lockSync(filepath);
    try {
        let count = parseInt(fs.readFileSync(filepath, 'utf8').trim(), 10) || 0;
        count++;
        fs.writeFileSync(filepath, String(count));
        return count;
    } finally {
        release();
    }
}
```

### Complexity Rationale
This is rated Nuanced because the race condition involves filesystem I/O rather than in-memory shared state. The vulnerability requires understanding that synchronous file operations interleaved with async task scheduling can still produce races.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not model file I/O operations as shared resources subject to race conditions, and the synchronous read-then-write pattern within an async context is not a standard detection rule.
