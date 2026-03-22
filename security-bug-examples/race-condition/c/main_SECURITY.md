# Security Companion Document: main.c

## Vulnerability: Non-Atomic Balance Update in Bank Transfer

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L21-L29  

### Description
The `do_transfers` function reads `alice->balance` into a local variable, yields the thread via `sched_yield()`, then writes back the modified value. When multiple threads execute concurrently, each reads the same stale balance and overwrites the others' updates, corrupting both account balances.

### Exploitation Scenario
An attacker triggers concurrent transfer operations. The interleaved read-modify-write operations on shared struct fields without any mutex protection cause money to be created or destroyed, breaking the total balance invariant.

### Remediation Guidance
Use a `pthread_mutex_t` to protect the balance updates:
```c
pthread_mutex_lock(&account_mutex);
ta->alice->balance -= 100;
ta->bob->balance += 100;
pthread_mutex_unlock(&account_mutex);
```

### Complexity Rationale
This is rated Obvious because the read-yield-write pattern on shared struct fields accessed from multiple pthreads is a textbook data race.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of reading a shared variable into a local, yielding, then writing it back without mutex protection is a well-known race condition pattern that SAST tools and thread sanitizers can identify.

---

## Vulnerability: TOCTOU in Ticket Booking

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L42-L49  

### Description
The `do_ticket_booking` function checks `ticket_available > 0`, yields, then decrements the global counter. Multiple threads pass the check simultaneously and all decrement, overselling tickets and potentially driving the counter negative.

### Exploitation Scenario
Concurrent booking threads all see tickets available before any decrement occurs, resulting in more tickets sold than the actual supply.

### Remediation Guidance
Protect the check-and-decrement with a mutex:
```c
pthread_mutex_lock(&ticket_mutex);
if (ticket_available > 0) {
    ticket_available--;
    ticket_sold++;
}
pthread_mutex_unlock(&ticket_mutex);
```

### Complexity Rationale
This is rated Obvious because the check-then-act pattern on global variables with an explicit yield between check and modification is a textbook TOCTOU vulnerability.

### Detection Difficulty Rationale
This is rated Easily_Detectable because unsynchronized access to global variables from multiple pthreads is a standard detection pattern for thread sanitizers and SAST tools.

---

## Vulnerability: Non-Atomic Shared Counter Increment

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L57-L62  

### Description
The `do_increment` function reads the global `shared_counter` into a local, yields, then writes back the incremented value. Concurrent threads overwrite each other's increments, resulting in a final count far lower than expected.

### Exploitation Scenario
Concurrent counter increments lose updates due to the read-yield-write pattern, exploitable in systems using counters for rate limiting or sequence generation.

### Remediation Guidance
Use atomic operations or a mutex:
```c
pthread_mutex_lock(&counter_mutex);
shared_counter++;
pthread_mutex_unlock(&counter_mutex);
```

### Complexity Rationale
This is rated Obvious because the read-yield-write pattern on a global variable is the most basic form of a data race in C.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the read-modify-write pattern on a global variable accessed from multiple pthreads is a standard SAST and thread sanitizer detection rule.

---

## Vulnerability: TOCTOU in Inventory Order Processing

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L72-L80  

### Description
The `do_place_orders` function reads `inventory_stock` into a local, checks if stock is positive, yields, then writes back the decremented value. Concurrent order threads read the same stock level and all succeed, driving inventory negative.

### Exploitation Scenario
Multiple concurrent order threads all pass the stock check before any update occurs, resulting in more items sold than physically exist.

### Remediation Guidance
Protect the stock check and update with a mutex:
```c
pthread_mutex_lock(&inventory_mutex);
if (inventory_stock > 0) {
    inventory_stock--;
    order_count++;
}
pthread_mutex_unlock(&inventory_mutex);
```

### Complexity Rationale
This is rated Moderate because the vulnerability involves both a TOCTOU check and a separate restock thread modifying the same global, requiring the reviewer to reason about multiple concurrent access patterns.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to recognize the TOCTOU pattern across the check-yield-write sequence and correlate it with the concurrent restock function.

---

## Vulnerability: Non-Atomic Restock Update

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L82-L87  

### Description
The `do_restock` function reads `inventory_stock` into a local, yields, then writes back the incremented value. This races with both the order processing thread and other potential restock threads, causing lost restocks.

### Exploitation Scenario
A restock operation reads the current stock, but before writing back, an order thread decrements the stock. The restock then overwrites with the stale value, effectively undoing the order's decrement.

### Remediation Guidance
Use the same inventory mutex for restock operations:
```c
pthread_mutex_lock(&inventory_mutex);
inventory_stock += 1;
pthread_mutex_unlock(&inventory_mutex);
```

### Complexity Rationale
This is rated Moderate because the race involves interaction between two different thread functions (order and restock) accessing the same global variable, requiring cross-function analysis.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to correlate unsynchronized access to the same global variable across two different thread entry point functions.

---

## Vulnerability: Non-Thread-Safe Singleton Config Initialization

**CWE:** CWE-362  
**OWASP:** null  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L93-L101  

### Description
The `do_init_config` function checks the global `config_ready` flag, yields, then allocates and initializes `config_data`. Multiple threads can pass the flag check simultaneously, causing multiple allocations where only the last one is retained, leaking memory and potentially using partially initialized data.

### Exploitation Scenario
Multiple threads simultaneously enter the initialization block. One thread allocates memory and sets `config_ready`, but another thread has already passed the check and allocates again, overwriting the pointer and leaking the first allocation. If a thread reads `config_data` between allocation and `strcpy`, it accesses uninitialized memory.

### Remediation Guidance
Use `pthread_once` for one-time initialization:
```c
static pthread_once_t config_once = PTHREAD_ONCE_INIT;

void init_config(void) {
    config_data = malloc(256);
    strcpy(config_data, "initialized");
    config_ready = 1;
}

void *do_init_config(void *arg) {
    pthread_once(&config_once, init_config);
    return NULL;
}
```

### Complexity Rationale
This is rated Nuanced because the race condition involves both a flag check and a memory allocation/initialization sequence. The reviewer must reason about the ordering of `malloc`, `strcpy`, and the flag assignment across threads, including the possibility of reading uninitialized memory.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically do not model the interaction between flag-guarded initialization and memory allocation in multi-threaded contexts, and the memory leak aspect adds a secondary vulnerability that is easy to overlook.
