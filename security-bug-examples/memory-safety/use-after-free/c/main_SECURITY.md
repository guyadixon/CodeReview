# Security Companion Document: main.c

## Language Exclusion Note: Python, Java, Go, Rust, and JavaScript

Python, Java, Go, and JavaScript are excluded from the Use After Free (CWE-416) vulnerability class because these languages use garbage collection for automatic memory management. Objects are not deallocated while any reference to them exists, so accessing a previously referenced object never results in use-after-free. Python uses reference counting with a cycle collector, Java and Go use tracing garbage collectors, and JavaScript relies on its engine's garbage collector. In all four languages, memory is only reclaimed when no live references remain, making CWE-416 impossible under normal operation.

Rust is excluded because its ownership and borrowing system prevents use-after-free at compile time. The borrow checker ensures that references cannot outlive the data they point to, and moving ownership invalidates the original binding. Attempting to use a value after it has been moved or dropped results in a compile-time error, not a runtime vulnerability.

---

## Vulnerability: Use After Free in complete_and_remove

**CWE:** CWE-416
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L101-L115

### Description
The `complete_and_remove` function obtains a pointer to a `Task` via `find_task_by_id`, marks it as completed, then calls `remove_task` which frees the task's memory. After the free, the function dereferences the stale `task` pointer to print the task's `id` and `label` fields, reading from freed heap memory.

### Exploitation Scenario
An attacker runs `./task-manager complete`. The function frees the task at index matching id 2, then reads `task->id` and `task->label` from the freed allocation. If the allocator has reused the memory for another allocation between the free and the read, the attacker can influence what data is printed or cause a crash. In a more complex application, this pattern could leak sensitive data from a reallocated object or be chained with heap spraying to achieve code execution.

### Remediation Guidance
Copy the needed fields before freeing:
```c
static void complete_and_remove(TaskList *list, int id) {
    Task *task = find_task_by_id(list, id);
    if (!task) return;
    task->completed = 1;
    int saved_id = task->id;
    char saved_label[LABEL_LEN];
    strncpy(saved_label, task->label, LABEL_LEN);
    printf("Completed task %d: %s\n", saved_id, saved_label);
    for (int i = 0; i < list->count; i++) {
        if (list->items[i]->id == id) {
            remove_task(list, i);
            break;
        }
    }
    printf("Post-removal check: task %d label = %s\n", saved_id, saved_label);
}
```

### Complexity Rationale
This is rated Obvious because the `free` (inside `remove_task`) and the subsequent dereference of `task` occur within the same short function, making the use-after-free pattern immediately visible during code review.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the pointer from `find_task_by_id` through `remove_task` (which calls `free`) and detect the subsequent dereference on the same pointer.

---

## Vulnerability: Use After Free via Stale Notification Callbacks

**CWE:** CWE-416
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L62-L75

### Description
The `notify_on_complete` function stores a raw pointer to a `Task` in the global `pending_notifications` array. When `remove_task` is later called, it frees the task's memory, but the notification entry still holds the stale pointer. When `fire_notifications` iterates the array and invokes the callback, it passes the freed pointer to `print_task_status`, which dereferences it to read `id`, `label`, `priority`, and `completed`.

### Exploitation Scenario
An attacker runs `./task-manager notify`. Two tasks are registered for notification, then both are removed via `remove_task`. When `fire_notifications` executes, it calls `print_task_status` with pointers to freed memory. If the heap has been reused, the callback reads attacker-influenced data. In a real application with user-controlled allocations between the free and the callback, this could leak sensitive information or be leveraged for control-flow hijacking via a corrupted function pointer.

### Remediation Guidance
Nullify notification targets when tasks are removed, or use an index-based approach:
```c
static void remove_task(TaskList *list, int index) {
    if (index < 0 || index >= list->count) return;
    Task *removed = list->items[index];
    for (int i = 0; i < notification_count; i++) {
        if (pending_notifications[i].target == removed) {
            pending_notifications[i].target = NULL;
        }
    }
    free(removed);
    for (int i = index; i < list->count - 1; i++) {
        list->items[i] = list->items[i + 1];
    }
    list->count--;
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans multiple functions (`notify_on_complete`, `remove_task`, `fire_notifications`) and requires understanding that the global notification array retains stale pointers after the task is freed elsewhere.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to track the pointer stored in the global array, recognize that `remove_task` frees the pointed-to memory, and detect that `fire_notifications` later dereferences the stale pointer through the callback.

---

## Vulnerability: Double Free in duplicate_and_free

**CWE:** CWE-416
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L143-L155

### Description
The `duplicate_and_free` function calls `free(original)` twice in succession on the same pointer. The first `free` releases the memory, and the second `free` operates on an already-freed pointer. This is undefined behavior that corrupts the heap allocator's internal data structures.

### Exploitation Scenario
An attacker runs `./task-manager duplicate`. The double free corrupts the heap metadata. Depending on the allocator implementation, this can lead to the allocator returning the same memory region for two different allocations, enabling heap-based exploitation techniques such as overlapping allocations, arbitrary write primitives, or code execution via overwritten function pointers.

### Remediation Guidance
Remove the duplicate `free` call and set the pointer to NULL after freeing:
```c
static void duplicate_and_free(TaskList *list) {
    if (list->count == 0) return;
    Task *original = list->items[0];
    Task *copy = (Task *)malloc(sizeof(Task));
    if (!copy) return;
    memcpy(copy, original, sizeof(Task));
    free(original);
    original = NULL;
    list->items[0] = copy;
    printf("Duplicated task: %s\n", copy->label);
}
```

### Complexity Rationale
This is rated Obvious because two consecutive `free(original)` calls on the same pointer within the same function are immediately recognizable as a double-free bug.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trivially detect two `free` calls on the same variable within the same basic block without any intervening reassignment.

---

## Vulnerability: Use After Free in archive_tasks via Stale Archived Pointers

**CWE:** CWE-416
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L157-L178

### Description
The `archive_tasks` function first collects pointers to completed tasks into a local `archived[]` array. It then iterates the task list in reverse, freeing completed tasks and compacting the list. Finally, it iterates `archived[]` and dereferences the stored pointers to print task details. Since the tasks were already freed in the removal loop, the print loop reads from freed heap memory.

### Exploitation Scenario
An attacker runs `./task-manager archive` after marking tasks as completed. The function frees the completed tasks, then reads `archived[i]->id` and `archived[i]->label` from freed memory. If the allocator has reused the freed regions (e.g., due to intervening `printf` allocations), the printed data may contain heap metadata or data from other allocations, leaking sensitive information.

### Remediation Guidance
Copy the needed data before freeing, or print before removing:
```c
static void archive_tasks(TaskList *list) {
    printf("Archived tasks:\n");
    for (int i = 0; i < list->count; i++) {
        if (list->items[i]->completed) {
            printf("  [%d] %s\n", list->items[i]->id, list->items[i]->label);
        }
    }
    for (int i = list->count - 1; i >= 0; i--) {
        if (list->items[i]->completed) {
            free(list->items[i]);
            for (int j = i; j < list->count - 1; j++) {
                list->items[j] = list->items[j + 1];
            }
            list->count--;
        }
    }
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding the two-phase pattern: the first loop collects pointers, the second loop frees the underlying memory, and the third loop dereferences the now-stale pointers. The separation between collection, freeing, and use makes it less immediately obvious.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track pointer aliasing between `list->items[i]` and `archived[]`, recognize that the removal loop frees the same objects, and detect that the final print loop dereferences stale pointers from the local array.

---

## Vulnerability: Use After Free via Stale Pointer After realloc Failure

**CWE:** CWE-416
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L130-L138

### Description
In `build_summary`, when `realloc` is needed to grow the buffer, the old pointer is saved in `old`. If `realloc` returns a new pointer, `old` becomes stale. However, the critical path is when `realloc` fails and returns NULL: the code calls `free(old)` and returns NULL, which is correct. But the more subtle issue is that `realloc` may succeed and return a different pointer, invalidating `old`. The code correctly reassigns `summary` but retains `old` on the stack. In a more complex variant, if error handling were to reference `old` after a successful realloc that moved the buffer, it would access freed memory. The current code's pattern of saving the old pointer before realloc establishes a dangerous idiom that leads to use-after-free when the pattern is extended or copied.

### Exploitation Scenario
When `realloc` succeeds but moves the allocation, the `old` pointer on the stack points to freed memory. While the current code does not dereference `old` after a successful realloc, the `printf` in the failure path prints the raw pointer value of `old` after calling `free(old)`, which is a minor information leak. In a modified version where the failure path attempts to use `old` as a fallback buffer (a common copy-paste error), this becomes a full use-after-free. The pattern is dangerous because it normalizes holding stale pointers across realloc boundaries.

### Remediation Guidance
Use a single-variable realloc pattern that avoids retaining the old pointer:
```c
if (offset + needed + 1 > (int)buf_size) {
    buf_size = (offset + needed + 1) * 2;
    char *tmp = (char *)realloc(summary, buf_size);
    if (!tmp) {
        free(summary);
        return NULL;
    }
    summary = tmp;
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability involves understanding realloc semantics (the old pointer is invalidated on success), recognizing the dangerous pattern of saving the old pointer, and evaluating the failure path where the freed pointer's address is printed. The actual exploitability depends on how the pattern is used in context.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically focus on the NULL-return path of realloc and may not flag the retention of the old pointer as a use-after-free risk. The information leak via `printf` of a freed pointer address is a subtle issue that most tools do not model.
