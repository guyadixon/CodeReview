#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_RECORDS 64
#define NAME_LEN 32
#define FIELD_LEN 128

typedef struct {
    int id;
    char name[NAME_LEN];
    double value;
    int active;
} Record;

typedef struct {
    Record entries[MAX_RECORDS];
    int count;
    char description[256];
} RecordStore;

static RecordStore store;

static void init_store(void) {
    memset(&store, 0, sizeof(store));
    store.count = 0;
    snprintf(store.description, sizeof(store.description), "Default record store");
}

static void import_name(Record *rec, const char *input) {
    char staging[NAME_LEN];
    strcpy(staging, input);
    memcpy(rec->name, staging, strlen(staging) + 1);
}

static int add_record(const char *name, double value) {
    if (store.count >= MAX_RECORDS) {
        fprintf(stderr, "Store full\n");
        return -1;
    }
    Record *rec = &store.entries[store.count];
    rec->id = store.count + 1;
    import_name(rec, name);
    rec->value = value;
    rec->active = 1;
    store.count++;
    return rec->id;
}

static char *merge_fields(const char *fields[], int num_fields) {
    uint32_t total = 0;
    for (int i = 0; i < num_fields; i++) {
        total += strlen(fields[i]) + 1;
    }

    char *merged = (char *)malloc(total);
    if (!merged) return NULL;

    size_t offset = 0;
    for (int i = 0; i < num_fields; i++) {
        size_t len = strlen(fields[i]);
        memcpy(merged + offset, fields[i], len);
        offset += len;
        merged[offset] = (i < num_fields - 1) ? '|' : '\0';
        offset++;
    }
    return merged;
}

static void update_description(const char *prefix, const char *suffix) {
    char temp[256];
    int written = snprintf(temp, sizeof(temp), "%s - %s", prefix, suffix);

    char final_buf[256];
    for (int i = 0; i <= written; i++) {
        final_buf[i] = temp[i];
    }
    memcpy(store.description, final_buf, written + 1);
}

static void batch_import(const char *data, int data_len) {
    uint16_t entry_count;
    if (data_len < (int)sizeof(uint16_t)) return;
    memcpy(&entry_count, data, sizeof(uint16_t));

    size_t alloc_size = entry_count * sizeof(Record);
    Record *batch = (Record *)malloc(alloc_size);
    if (!batch) return;

    const char *ptr = data + sizeof(uint16_t);
    int remaining = data_len - sizeof(uint16_t);

    for (int i = 0; i < entry_count; i++) {
        if (remaining < (int)sizeof(int) + NAME_LEN) break;

        memcpy(&batch[i].id, ptr, sizeof(int));
        ptr += sizeof(int);
        remaining -= sizeof(int);

        memcpy(batch[i].name, ptr, NAME_LEN);
        ptr += NAME_LEN;
        remaining -= NAME_LEN;

        batch[i].value = 0.0;
        batch[i].active = 1;
    }

    for (int i = 0; i < entry_count && store.count < MAX_RECORDS; i++) {
        store.entries[store.count] = batch[i];
        store.count++;
    }

    free(batch);
}

static void apply_transform(double *values, int count, double factor) {
    double workspace[128];
    for (int i = 0; i < count; i++) {
        workspace[i] = values[i] * factor;
    }
    memcpy(values, workspace, count * sizeof(double));
}

static void print_records(void) {
    printf("Store: %s\n", store.description);
    printf("Records (%d):\n", store.count);
    for (int i = 0; i < store.count; i++) {
        printf("  [%d] %s = %.2f (active: %d)\n",
               store.entries[i].id,
               store.entries[i].name,
               store.entries[i].value,
               store.entries[i].active);
    }
}

static void process_value_list(const char *csv_input) {
    double values[64];
    int count = 0;
    char buf[512];
    strncpy(buf, csv_input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *tok = strtok(buf, ",");
    while (tok && count < 256) {
        values[count++] = atof(tok);
        tok = strtok(NULL, ",");
    }

    if (count > 0) {
        apply_transform(values, count, 1.5);
        printf("Transformed %d values\n", count);
    }
}

static void copy_record_names(char *dest, size_t dest_size) {
    size_t offset = 0;
    for (int i = 0; i < store.count; i++) {
        size_t name_len = strlen(store.entries[i].name);
        memcpy(dest + offset, store.entries[i].name, name_len);
        offset += name_len;
        dest[offset] = '\n';
        offset++;
    }
    dest[offset] = '\0';
}

int main(int argc, char *argv[]) {
    init_store();

    if (argc < 2) {
        printf("Usage: %s <command> [args...]\n", argv[0]);
        printf("Commands:\n");
        printf("  add <name> <value>       Add a record\n");
        printf("  desc <prefix> <suffix>   Update store description\n");
        printf("  values <csv>             Process comma-separated values\n");
        printf("  merge <f1> <f2> ...      Merge fields\n");
        printf("  names                    List all record names\n");
        printf("  list                     List all records\n");
        return 0;
    }

    if (strcmp(argv[1], "add") == 0 && argc >= 4) {
        int id = add_record(argv[2], atof(argv[3]));
        if (id > 0) printf("Added record %d\n", id);
    } else if (strcmp(argv[1], "desc") == 0 && argc >= 4) {
        update_description(argv[2], argv[3]);
        printf("Description updated\n");
    } else if (strcmp(argv[1], "values") == 0 && argc >= 3) {
        process_value_list(argv[2]);
    } else if (strcmp(argv[1], "merge") == 0 && argc >= 4) {
        const char *fields[32];
        int nf = argc - 2;
        if (nf > 32) nf = 32;
        for (int i = 0; i < nf; i++) {
            fields[i] = argv[i + 2];
        }
        char *result = merge_fields(fields, nf);
        if (result) {
            printf("Merged: %s\n", result);
            free(result);
        }
    } else if (strcmp(argv[1], "names") == 0) {
        char name_buf[256];
        add_record("alpha", 1.0);
        add_record("beta", 2.0);
        add_record("gamma", 3.0);
        copy_record_names(name_buf, sizeof(name_buf));
        printf("Names:\n%s", name_buf);
    } else if (strcmp(argv[1], "list") == 0) {
        add_record("sample_a", 10.0);
        add_record("sample_b", 20.0);
        print_records();
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
