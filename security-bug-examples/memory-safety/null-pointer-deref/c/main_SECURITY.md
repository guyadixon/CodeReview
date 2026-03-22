# Security Companion Document: main.c

## Language Exclusion Note: Python, JavaScript, and Rust

Python and JavaScript are excluded from the NULL Pointer Dereference (CWE-476) vulnerability class because these languages do not expose raw pointers. In Python, accessing an attribute on `None` raises an `AttributeError` exception that can be caught and handled, preventing undefined behavior or memory corruption. Similarly, in JavaScript, accessing a property on `null` or `undefined` raises a `TypeError` exception. While these exceptions can cause application crashes if unhandled, they do not produce the memory-safety consequences (segmentation faults, undefined behavior, potential code execution) that characterize CWE-476 in languages with raw pointers.

Rust is excluded because its type system prevents null pointer dereferences at compile time. Rust has no null value for references; instead, it uses the `Option<T>` enum to represent values that may or may not exist. The compiler forces the programmer to handle the `None` case before accessing the inner value, making it impossible to dereference a null pointer in safe Rust code. While `unsafe` blocks can create raw pointers, idiomatic Rust code avoids this pattern entirely.

---

## Vulnerability: NULL Pointer Dereference in get_config_value

**CWE:** CWE-476
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L113-L115

### Description
The `get_config_value` function calls `find_config` to look up a key. When the key does not exist in the store, `find_config` returns `NULL`. The function then immediately dereferences the result with `cfg->value` without checking for `NULL`, causing a segmentation fault.

### Exploitation Scenario
An attacker runs `./config-manager lookup nonexistent_key`. The `find_config` call returns `NULL` because the key does not exist in the store. The subsequent `cfg->value` dereference reads from address `0 + offsetof(Config, value)`, triggering a segmentation fault. In a program that installs a custom signal handler or runs on a system where address zero is mapped, this could lead to reading attacker-controlled data or bypassing security checks that depend on the function returning a valid value.

### Remediation Guidance
Check the return value of `find_config` before dereferencing:
```c
static char *get_config_value(ConfigStore *store, const char *key) {
    Config *cfg = find_config(store, key);
    if (!cfg) {
        return NULL;
    }
    return cfg->value;
}
```

### Complexity Rationale
This is rated Obvious because the `find_config` call and the unchecked dereference occur on consecutive lines within a three-line function, making the missing NULL check immediately visible.

### Detection Difficulty Rationale
This is rated Easily_Detectable because SAST tools can trace the return value of `find_config` (which has an explicit `return NULL` path) directly to the dereference on the next line without any intervening checks.

---

## Vulnerability: NULL Pointer Dereference in print_config_length

**CWE:** CWE-476
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L117-L119

### Description
The `print_config_length` function calls `find_config` and immediately passes `cfg->value` to `strlen` without verifying that `cfg` is not `NULL`. When the requested key does not exist, `find_config` returns `NULL`, and the `strlen(cfg->value)` call dereferences a null pointer.

### Exploitation Scenario
An attacker runs `./config-manager batch "len missing_key"`. The `find_config` call returns `NULL`, and `strlen` attempts to read from the null pointer offset, causing a segmentation fault. If the application is part of a larger service that processes batch commands, this crash can be used as a denial-of-service vector by including a nonexistent key in the batch input.

### Remediation Guidance
Add a NULL check before accessing the config value:
```c
static void print_config_length(ConfigStore *store, const char *key) {
    Config *cfg = find_config(store, key);
    if (!cfg) {
        printf("Config '%s' not found\n", key);
        return;
    }
    printf("Config '%s' value length: %zu\n", key, strlen(cfg->value));
}
```

### Complexity Rationale
This is rated Obvious because the pattern is identical to `get_config_value`: a direct dereference of the `find_config` return value without a NULL check, all within a three-line function.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the data flow from `find_config` (which can return NULL) to the dereference is a single step with no intervening logic.

---

## Vulnerability: NULL Pointer Dereference in merge_values

**CWE:** CWE-476
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L121-L128

### Description
The `merge_values` function calls `find_config` twice to look up two keys, then dereferences both `c1->value` and `c2->value` in the `strlen` and `snprintf` calls. If either key does not exist, the corresponding pointer is `NULL`, and the dereference causes a segmentation fault. The vulnerability involves two separate lookup-and-dereference chains that both need validation.

### Exploitation Scenario
An attacker runs `./config-manager merge database_host nonexistent_key`. The first `find_config` succeeds, but the second returns `NULL`. The `strlen(c2->value)` call dereferences the null pointer. An attacker could also supply two nonexistent keys to trigger the crash on `c1->value` instead. This provides a reliable denial-of-service against any batch processing that merges configuration values.

### Remediation Guidance
Validate both pointers before use:
```c
static char *merge_values(ConfigStore *store, const char *key1, const char *key2) {
    Config *c1 = find_config(store, key1);
    Config *c2 = find_config(store, key2);
    if (!c1 || !c2) return NULL;

    size_t len = strlen(c1->value) + strlen(c2->value) + 2;
    char *merged = (char *)malloc(len);
    if (!merged) return NULL;
    snprintf(merged, len, "%s:%s", c1->value, c2->value);
    return merged;
}
```

### Complexity Rationale
This is rated Moderate because while each individual dereference follows the same pattern as `get_config_value`, the function involves two separate pointers that both need validation, and the dereferences are embedded within `strlen` and `snprintf` calls rather than being direct field accesses.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track two separate `find_config` return values through the function and recognize that both are dereferenced without NULL checks. Some tools may flag one but miss the other.

---

## Vulnerability: NULL Pointer Dereference in load_from_input via parse_line Error

**CWE:** CWE-476
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L103-L111

### Description
The `load_from_input` function calls `parse_line` for each line of input. When `parse_line` encounters a line without an `=` character, it returns a `ParseResult` with `key = NULL`, `value = NULL`, and `error_code = -1`. Similarly, when the value portion is empty, `parse_line` returns with `key` set but `value = NULL` and `error_code = -2`. The `load_from_input` function does not check `error_code` or the NULL fields before passing `pr.key` and `pr.value` to `printf` and `add_config`, causing NULL pointer dereferences.

### Exploitation Scenario
An attacker runs `./config-manager load "invalid_line_without_equals"`. The `parse_line` function returns `{NULL, NULL, -1}`. The `printf("Loaded: %s = %s\n", pr.key, pr.value)` call passes NULL to `%s`, which is undefined behavior in C (some implementations print "(null)" but this is not guaranteed). The subsequent `add_config(store, pr.key, pr.value)` passes NULL to `strncpy` inside `create_config`, causing a segmentation fault.

### Remediation Guidance
Check the parse result before using it:
```c
static void load_from_input(ConfigStore *store, const char *input) {
    char *copy = strdup(input);
    char *line = strtok(copy, "\n");

    while (line) {
        ParseResult pr = parse_line(line);
        if (pr.error_code != 0 || !pr.key || !pr.value) {
            free(pr.key);
            free(pr.value);
            line = strtok(NULL, "\n");
            continue;
        }
        printf("Loaded: %s = %s\n", pr.key, pr.value);
        add_config(store, pr.key, pr.value);
        free(pr.key);
        free(pr.value);
        line = strtok(NULL, "\n");
    }

    free(copy);
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability requires understanding the `parse_line` function's error-return semantics (multiple error codes, partial initialization of the result struct) and recognizing that the caller does not check any of these conditions.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to determine that `parse_line` can return NULL fields, and must trace those NULL values through the `printf` and `add_config` calls.

---

## Vulnerability: NULL Pointer Dereference in export_configs After malloc Failure

**CWE:** CWE-476
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L130-L148

### Description
The `export_configs` function allocates a buffer with `malloc`. If `malloc` fails and returns `NULL`, the code proceeds to the `snprintf` loop which writes to `buffer + offset` (a NULL-based offset), causing a segmentation fault. Additionally, if `realloc` fails inside the loop, the code sets `buffer = NULL` and breaks, but then falls through to `printf("%s", buffer)` which passes NULL to `%s`, invoking undefined behavior.

### Exploitation Scenario
On a memory-constrained system or when processing a large number of configuration entries, `malloc` or `realloc` may fail. If `realloc` fails mid-loop, `buffer` is set to NULL after freeing the old allocation, and the function falls through to `printf("%s", buffer)`. Passing NULL to `printf`'s `%s` format specifier is undefined behavior that can crash the process or, on some platforms, print from an attacker-influenced memory location. An attacker who can control the number of configuration entries (e.g., via repeated `load` commands) can trigger memory pressure to force the allocation failure.

### Remediation Guidance
Check for allocation failure and guard the final printf:
```c
static void export_configs(ConfigStore *store) {
    size_t buf_size = 256;
    char *buffer = (char *)malloc(buf_size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    int offset = 0;

    for (int i = 0; i < store->count; i++) {
        int needed = snprintf(NULL, 0, "%s=%s\n",
                              store->entries[i]->key,
                              store->entries[i]->value);

        if (offset + needed + 1 > (int)buf_size) {
            buf_size = (offset + needed + 1) * 2;
            char *new_buf = (char *)realloc(buffer, buf_size);
            if (!new_buf) {
                free(buffer);
                fprintf(stderr, "Memory reallocation failed\n");
                return;
            }
            buffer = new_buf;
        }

        offset += snprintf(buffer + offset, buf_size - offset,
                           "%s=%s\n",
                           store->entries[i]->key,
                           store->entries[i]->value);
    }

    printf("%s", buffer);
    free(buffer);
}
```

### Complexity Rationale
This is rated Nuanced because the vulnerability depends on understanding memory allocation failure paths. The initial `malloc` failure is straightforward, but the `realloc` failure path is more subtle: the code correctly frees the old buffer and sets `buffer = NULL`, but then falls through to `printf` with the NULL pointer. Recognizing this requires tracing the control flow through the loop's break condition to the final printf.

### Detection Difficulty Rationale
This is rated Likely_Missed because SAST tools typically focus on the common case where allocations succeed. The `realloc` failure path that sets `buffer = NULL` and then falls through to `printf("%s", buffer)` requires path-sensitive analysis through the loop, which many tools do not perform thoroughly.
