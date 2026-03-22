# Security Companion Document: main.cpp

## Language Exclusion Note: Python, Java, Go, Rust, and JavaScript

Python, Java, Go, and JavaScript are excluded from the Use After Free (CWE-416) vulnerability class because these languages use garbage collection for automatic memory management. Objects are not deallocated while any reference to them exists, so accessing a previously referenced object never results in use-after-free. Python uses reference counting with a cycle collector, Java and Go use tracing garbage collectors, and JavaScript relies on its engine's garbage collector. In all four languages, memory is only reclaimed when no live references remain, making CWE-416 impossible under normal operation.

Rust is excluded because its ownership and borrowing system prevents use-after-free at compile time. The borrow checker ensures that references cannot outlive the data they point to, and moving ownership invalidates the original binding. Attempting to use a value after it has been moved or dropped results in a compile-time error, not a runtime vulnerability.

---

## Vulnerability: Use After Free via Dangling Pointer After Document Removal

**CWE:** CWE-416
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L170-L176

### Description
The `demo_dangling_after_remove` function obtains a pointer to a `Document` via `store.get(1)`, then calls `store.remove(1)` which frees the document's content and deletes the `Document` object. After the removal, the function dereferences the stale `ref` pointer to access `ref->title` and `ref->content_len`, reading from freed heap memory.

### Exploitation Scenario
An attacker runs `./doc-store dangling`. The `store.remove(1)` call deletes the document and frees its content buffer. The subsequent reads of `ref->title` and `ref->content_len` access freed memory. If the allocator has reused the freed region for another allocation, the attacker can influence what data is read, potentially leaking sensitive information from a different object that now occupies the same memory.

### Remediation Guidance
Copy the needed fields before removing:
```cpp
static void demo_dangling_after_remove(DocumentStore &store) {
    Document *ref = store.get(1);
    std::string saved_title(ref->title);
    size_t saved_len = ref->content_len;
    std::cout << "Before remove - doc: " << saved_title << std::endl;
    store.remove(1);
    std::cout << "After remove - doc: " << saved_title << std::endl;
    std::cout << "After remove - content length: " << saved_len << std::endl;
}
```

### Complexity Rationale
This is rated Obvious because the `store.remove(1)` and the subsequent dereference of `ref` occur within the same short function with no intervening logic, making the use-after-free immediately visible.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the pointer from `store.get(1)` through `store.remove(1)` (which calls `delete`) and detect the subsequent dereference on the same pointer.

---

## Vulnerability: Use After Free via EventBus Holding Stale Document Pointers

**CWE:** CWE-416
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L178-L188

### Description
The `demo_event_bus` function subscribes three document pointers to an `EventBus`. When `store.remove(1)` is called, the second document is freed, but the `EventBus` still holds the stale pointer in its `listeners_` vector. When `bus.publish()` iterates the listeners and invokes the handler, it passes the freed pointer to `print_document_event`, which dereferences it to read `doc->id` and `doc->title`.

### Exploitation Scenario
An attacker runs `./doc-store events`. After `store.remove(1)` frees the document, `bus.publish()` invokes the callback with the stale pointer. The `print_document_event` function reads `doc->id` and `doc->title` from freed memory. If the heap has been reused between the free and the callback invocation, the attacker can control what data the callback reads, potentially leaking sensitive information or causing a crash.

### Remediation Guidance
Use indices or weak references instead of raw pointers, or unsubscribe before removal:
```cpp
static void demo_event_bus(DocumentStore &store) {
    EventBus bus;
    bus.subscribe(store.get(0), print_document_event);
    bus.subscribe(store.get(2), print_document_event);
    store.remove(1);
    std::cout << "Publishing events after removal:" << std::endl;
    bus.publish();
    bus.clear();
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans the `EventBus` class and the `demo_event_bus` function, requiring understanding that the observer pattern stores raw pointers that become stale when the observed object is deleted elsewhere.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to track pointers stored in the `EventBus::listeners_` vector, recognize that `store.remove` deletes the pointed-to object, and detect that `publish()` later dereferences the stale pointer through the `std::function` callback.

---

## Vulnerability: Use After Free via Shallow Content Copy in fetch_and_release

**CWE:** CWE-416
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L107-L117

### Description
The `fetch_and_release` function creates a `snapshot` document and shallow-copies the `content` pointer from the original document (`snapshot->content = doc->content`). It then calls `store.remove(index)`, which frees the original document's content buffer via `free(docs_[index]->content)`. The snapshot now holds a dangling pointer to freed memory. When the caller accesses `snap->content`, it reads from freed heap memory.

### Exploitation Scenario
An attacker runs `./doc-store snapshot`. The `fetch_and_release` function copies the raw `content` pointer, then `store.remove(0)` frees the content buffer. The caller in `demo_snapshot` prints `snap->content`, reading from freed memory. Additionally, `demo_snapshot` calls `std::free(snap->content)` on the already-freed pointer, causing a double free that corrupts the heap allocator.

### Remediation Guidance
Deep-copy the content buffer instead of shallow-copying the pointer:
```cpp
static Document *fetch_and_release(DocumentStore &store, int index) {
    Document *doc = store.get(index);
    if (!doc) return nullptr;
    Document *snapshot = new Document;
    snapshot->id = doc->id;
    std::strcpy(snapshot->title, doc->title);
    snapshot->content_len = doc->content_len;
    snapshot->content = (char *)std::malloc(doc->content_len + 1);
    std::memcpy(snapshot->content, doc->content, doc->content_len + 1);
    store.remove(index);
    return snapshot;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding that the pointer assignment `snapshot->content = doc->content` creates an alias, and that `store.remove` frees the underlying buffer through the original document, invalidating the alias in the snapshot.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track pointer aliasing between `doc->content` and `snapshot->content`, recognize that `store.remove` frees the content through the original document, and detect that the snapshot's content pointer is subsequently dereferenced.

---

## Vulnerability: Double Free of Document Content Buffer

**CWE:** CWE-416
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L196-L205

### Description
The `demo_double_free` function saves a copy of the `content` pointer from a document, then calls `store.remove(0)` which frees the content buffer via `free(docs_[index]->content)` and deletes the document. The function then calls `std::free(content_ptr)` on the same buffer that was already freed by `store.remove`, resulting in a double free.

### Exploitation Scenario
An attacker runs `./doc-store doublefree`. The `store.remove(0)` call frees the content buffer, and the subsequent `std::free(content_ptr)` frees the same memory again. This corrupts the heap allocator's metadata, which can be exploited to achieve arbitrary write primitives. An attacker who can influence heap layout between the two frees can leverage this for code execution.

### Remediation Guidance
Remove the redundant free and nullify the pointer:
```cpp
static void demo_double_free(DocumentStore &store) {
    if (store.count() < 2) return;
    Document *d = store.get(0);
    store.remove(0);
    std::cout << "Released content buffer" << std::endl;
}
```

### Complexity Rationale
This is rated Obvious because the pattern of saving a pointer, calling a function that frees it, and then freeing it again is a straightforward double-free that is immediately recognizable during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can track the `content_ptr` alias to `d->content`, recognize that `store.remove` frees `content` internally, and flag the subsequent `std::free(content_ptr)` as a double free.

---

## Vulnerability: Use After Free via Stale Buffer in build_index After realloc

**CWE:** CWE-416
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L147-L165

### Description
In `build_index`, when the buffer needs to grow, `old_buf` is saved as a copy of `index_buf` before calling `resize_buffer`. The `resize_buffer` function calls `std::realloc`, and if realloc fails, it prints the old buffer address and frees it, returning nullptr. Back in `build_index`, when `resize_buffer` returns nullptr, the code prints `old_buf` via `std::cout << old_buf`, but `old_buf` points to memory that was already freed inside `resize_buffer`. This dereferences freed memory.

### Exploitation Scenario
An attacker triggers a scenario where `std::realloc` fails (e.g., under memory pressure). The `resize_buffer` function frees the buffer and returns nullptr. The `build_index` function then reads from `old_buf`, which points to the freed buffer. If the allocator has reused the memory, the output could contain sensitive data from another allocation. The information leak of the raw pointer address in `resize_buffer` also aids exploitation by defeating ASLR.

### Remediation Guidance
Do not retain the old pointer across the resize call:
```cpp
static void build_index(DocumentStore &store) {
    size_t buf_size = 64;
    char *index_buf = (char *)std::malloc(buf_size);
    if (!index_buf) return;
    int offset = std::snprintf(index_buf, buf_size, "Index:\n");
    for (int i = 0; i < store.count(); i++) {
        Document *d = store.get(i);
        int needed = std::snprintf(nullptr, 0, "  %d: %s\n", d->id, d->title);
        if (offset + needed + 1 > (int)buf_size) {
            buf_size = (offset + needed + 1) * 2;
            char *tmp = (char *)std::realloc(index_buf, buf_size);
            if (!tmp) {
                std::free(index_buf);
                return;
            }
            index_buf = tmp;
        }
        offset += std::snprintf(index_buf + offset, buf_size - offset,
                                "  %d: %s\n", d->id, d->title);
    }
    std::cout << index_buf;
    std::free(index_buf);
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability requires understanding the interaction between two functions (`build_index` and `resize_buffer`), the semantics of `realloc` (which may move or free the original buffer), and the specific failure path where the old pointer becomes stale after being freed inside the helper function.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools must trace the pointer through a helper function, understand that `resize_buffer` may free the buffer on the failure path, and detect that the caller still holds and dereferences the stale `old_buf` pointer. Most tools focus on the common realloc-NULL pattern and miss the cross-function stale pointer issue.
