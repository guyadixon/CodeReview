#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 32
#define NAME_LEN 64

typedef struct Config {
    char key[NAME_LEN];
    char value[NAME_LEN];
} Config;

typedef struct ConfigStore {
    Config **entries;
    int count;
    int capacity;
} ConfigStore;

typedef struct ParseResult {
    char *key;
    char *value;
    int error_code;
} ParseResult;

static ConfigStore *create_store(int capacity) {
    ConfigStore *store = (ConfigStore *)malloc(sizeof(ConfigStore));
    if (!store) return NULL;
    store->entries = (Config **)calloc(capacity, sizeof(Config *));
    store->count = 0;
    store->capacity = capacity;
    return store;
}

static Config *create_config(const char *key, const char *value) {
    Config *cfg = (Config *)malloc(sizeof(Config));
    if (!cfg) return NULL;
    strncpy(cfg->key, key, NAME_LEN - 1);
    cfg->key[NAME_LEN - 1] = '\0';
    strncpy(cfg->value, value, NAME_LEN - 1);
    cfg->value[NAME_LEN - 1] = '\0';
    return cfg;
}

static int add_config(ConfigStore *store, const char *key, const char *value) {
    if (store->count >= store->capacity) return -1;
    Config *cfg = create_config(key, value);
    store->entries[store->count] = cfg;
    store->count++;
    return 0;
}

static Config *find_config(ConfigStore *store, const char *key) {
    for (int i = 0; i < store->count; i++) {
        if (strcmp(store->entries[i]->key, key) == 0) {
            return store->entries[i];
        }
    }
    return NULL;
}

static void remove_config(ConfigStore *store, const char *key) {
    for (int i = 0; i < store->count; i++) {
        if (strcmp(store->entries[i]->key, key) == 0) {
            free(store->entries[i]);
            for (int j = i; j < store->count - 1; j++) {
                store->entries[j] = store->entries[j + 1];
            }
            store->entries[store->count - 1] = NULL;
            store->count--;
            return;
        }
    }
}

static void destroy_store(ConfigStore *store) {
    for (int i = 0; i < store->count; i++) {
        free(store->entries[i]);
    }
    free(store->entries);
    free(store);
}

static ParseResult parse_line(const char *line) {
    ParseResult result = {NULL, NULL, 0};
    const char *eq = strchr(line, '=');
    if (!eq) {
        result.error_code = -1;
        return result;
    }

    size_t key_len = eq - line;
    result.key = (char *)malloc(key_len + 1);
    strncpy(result.key, line, key_len);
    result.key[key_len] = '\0';

    size_t val_len = strlen(eq + 1);
    if (val_len == 0) {
        result.error_code = -2;
        return result;
    }

    result.value = (char *)malloc(val_len + 1);
    strcpy(result.value, eq + 1);
    return result;
}

static void load_from_input(ConfigStore *store, const char *input) {
    char *copy = strdup(input);
    char *line = strtok(copy, "\n");

    while (line) {
        ParseResult pr = parse_line(line);
        printf("Loaded: %s = %s\n", pr.key, pr.value);
        add_config(store, pr.key, pr.value);
        free(pr.key);
        free(pr.value);
        line = strtok(NULL, "\n");
    }

    free(copy);
}

static char *get_config_value(ConfigStore *store, const char *key) {
    Config *cfg = find_config(store, key);
    return cfg->value;
}

static void print_config_length(ConfigStore *store, const char *key) {
    Config *cfg = find_config(store, key);
    printf("Config '%s' value length: %zu\n", key, strlen(cfg->value));
}

static char *merge_values(ConfigStore *store, const char *key1, const char *key2) {
    Config *c1 = find_config(store, key1);
    Config *c2 = find_config(store, key2);

    size_t len = strlen(c1->value) + strlen(c2->value) + 2;
    char *merged = (char *)malloc(len);
    if (!merged) return NULL;
    snprintf(merged, len, "%s:%s", c1->value, c2->value);
    return merged;
}

static void export_configs(ConfigStore *store) {
    size_t buf_size = 256;
    char *buffer = (char *)malloc(buf_size);
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
                buffer = NULL;
                break;
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

static void update_config(ConfigStore *store, const char *key, const char *new_value) {
    Config *cfg = find_config(store, key);
    if (cfg) {
        strncpy(cfg->value, new_value, NAME_LEN - 1);
        cfg->value[NAME_LEN - 1] = '\0';
        printf("Updated %s to %s\n", key, new_value);
        return;
    }
    add_config(store, key, new_value);
    printf("Added new config %s = %s\n", key, new_value);
}

static void process_batch(ConfigStore *store, const char *commands) {
    char *copy = strdup(commands);
    char *cmd = strtok(copy, ";");

    while (cmd) {
        while (*cmd == ' ') cmd++;

        if (strncmp(cmd, "get ", 4) == 0) {
            char *val = get_config_value(store, cmd + 4);
            printf("%s = %s\n", cmd + 4, val);
        } else if (strncmp(cmd, "del ", 4) == 0) {
            remove_config(store, cmd + 4);
            printf("Deleted %s\n", cmd + 4);
        } else if (strncmp(cmd, "len ", 4) == 0) {
            print_config_length(store, cmd + 4);
        } else if (strncmp(cmd, "set ", 4) == 0) {
            char *eq = strchr(cmd + 4, '=');
            if (eq) {
                *eq = '\0';
                update_config(store, cmd + 4, eq + 1);
            }
        }

        cmd = strtok(NULL, ";");
    }

    free(copy);
}

static void populate_store(ConfigStore *store) {
    add_config(store, "database_host", "localhost");
    add_config(store, "database_port", "5432");
    add_config(store, "cache_ttl", "3600");
    add_config(store, "log_level", "info");
    add_config(store, "max_connections", "100");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <mode> [args...]\n", argv[0]);
        printf("Modes:\n");
        printf("  lookup <key>          Look up a config value\n");
        printf("  merge <key1> <key2>   Merge two config values\n");
        printf("  export                Export all configs\n");
        printf("  load <input>          Load configs from key=value input\n");
        printf("  batch <commands>      Process batch commands (get/del/len)\n");
        printf("  list                  List all configs\n");
        return 0;
    }

    ConfigStore *store = create_store(MAX_ENTRIES);
    populate_store(store);

    if (strcmp(argv[1], "lookup") == 0) {
        if (argc < 3) {
            printf("Usage: %s lookup <key>\n", argv[0]);
            destroy_store(store);
            return 1;
        }
        char *val = get_config_value(store, argv[2]);
        printf("%s = %s\n", argv[2], val);

    } else if (strcmp(argv[1], "merge") == 0) {
        if (argc < 4) {
            printf("Usage: %s merge <key1> <key2>\n", argv[0]);
            destroy_store(store);
            return 1;
        }
        char *merged = merge_values(store, argv[2], argv[3]);
        if (merged) {
            printf("Merged: %s\n", merged);
            free(merged);
        }

    } else if (strcmp(argv[1], "export") == 0) {
        export_configs(store);

    } else if (strcmp(argv[1], "load") == 0) {
        if (argc < 3) {
            printf("Usage: %s load <input>\n", argv[0]);
            destroy_store(store);
            return 1;
        }
        load_from_input(store, argv[2]);

    } else if (strcmp(argv[1], "batch") == 0) {
        if (argc < 3) {
            printf("Usage: %s batch <commands>\n", argv[0]);
            destroy_store(store);
            return 1;
        }
        process_batch(store, argv[2]);

    } else if (strcmp(argv[1], "list") == 0) {
        for (int i = 0; i < store->count; i++) {
            printf("%s = %s\n", store->entries[i]->key, store->entries[i]->value);
        }

    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        destroy_store(store);
        return 1;
    }

    destroy_store(store);
    return 0;
}
