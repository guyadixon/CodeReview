#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>

#define MAX_USERS 16
#define MAX_SESSIONS 64
#define MAX_TRANSACTIONS 256
#define MAX_POST_SIZE 4096
#define PORT 9089

struct user {
    int id;
    char username[64];
    char email[128];
    char password[128];
    char role[32];
    int active;
    int mfa_enabled;
    char api_key[64];
};

struct session {
    char token[65];
    int user_id;
    time_t created;
};

struct transaction {
    int id;
    int user_id;
    double amount;
    char recipient[128];
    char description[256];
    time_t timestamp;
    char status[16];
};

static struct user users[MAX_USERS];
static int user_count = 0;
static struct session sessions[MAX_SESSIONS];
static int session_count = 0;
static struct transaction transactions[MAX_TRANSACTIONS];
static int transaction_count = 0;

static void init_data(void) {
    struct user defaults[] = {
        {1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", 1, 1, "ak-admin-x7k9m2"},
        {2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", 1, 0, "ak-jdoe-p3q8r1"},
        {3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", 1, 0, "ak-asmith-w5t6y4"},
        {4, "bwilson", "bwilson@acmecorp.io", "B0b_W1ls0n", "analyst", 0, 0, "ak-bwilson-z2v8n3"},
    };
    user_count = 4;
    memcpy(users, defaults, sizeof(defaults));
}

static void simple_hash(const char *input, char *output, size_t out_sz) {
    unsigned long h = 5381;
    for (const char *p = input; *p; p++)
        h = ((h << 5) + h) + (unsigned char)*p;
    snprintf(output, out_sz, "%016lx", h);
}

static const char *create_session(int user_id) {
    if (session_count >= MAX_SESSIONS) return NULL;
    struct session *s = &sessions[session_count++];
    char raw[128];
    snprintf(raw, sizeof(raw), "%d-%ld", user_id, (long)time(NULL));
    simple_hash(raw, s->token, sizeof(s->token));
    s->user_id = user_id;
    s->created = time(NULL);
    return s->token;
}

static int find_session(const char *token) {
    for (int i = 0; i < session_count; i++) {
        if (strcmp(sessions[i].token, token) == 0)
            return sessions[i].user_id;
    }
    return -1;
}

static int get_session_user(struct MHD_Connection *conn) {
    const char *auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
    if (auth && strncmp(auth, "Bearer ", 7) == 0) {
        return find_session(auth + 7);
    }
    return -1;
}

static struct user *find_user_by_id(int id) {
    for (int i = 0; i < user_count; i++) {
        if (users[i].id == id) return &users[i];
    }
    return NULL;
}

static struct user *find_user_by_username(const char *username) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) return &users[i];
    }
    return NULL;
}

static const char *extract_json_string(const char *json, const char *key, char *buf, size_t buf_sz) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return NULL;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return NULL;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < buf_sz - 1) {
            buf[i++] = *p++;
        }
        buf[i] = '\0';
        return buf;
    }
    return NULL;
}

static double extract_json_number(const char *json, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0.0;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return 0.0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return atof(p);
}

static enum MHD_Result send_json(struct MHD_Connection *conn, int status, const char *json_str) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result handle_login(struct MHD_Connection *conn, const char *body) {
    char username[64] = {0}, password[128] = {0};
    extract_json_string(body, "username", username, sizeof(username));
    extract_json_string(body, "password", password, sizeof(password));

    struct user *u = find_user_by_username(username);
    if (!u) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Invalid credentials\"}");
    }

    if (!u->active) {
        return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Account disabled\"}");
    }

    if (strcmp(u->password, password) == 0) {
        const char *token = create_session(u->id);
        char resp[512];
        snprintf(resp, sizeof(resp),
                 "{\"token\":\"%s\",\"user_id\":%d,\"role\":\"%s\","
                 "\"password\":\"%s\",\"api_key\":\"%s\"}",
                 token, u->id, u->role, u->password, u->api_key);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Invalid credentials\"}");
}

static enum MHD_Result handle_list_users(struct MHD_Connection *conn) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    char resp[4096] = "{\"users\":[";
    for (int i = 0; i < user_count; i++) {
        char entry[512];
        snprintf(entry, sizeof(entry),
                 "%s{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\","
                 "\"role\":\"%s\",\"active\":%s}",
                 i > 0 ? "," : "",
                 users[i].id, users[i].username, users[i].email,
                 users[i].role, users[i].active ? "true" : "false");
        strncat(resp, entry, sizeof(resp) - strlen(resp) - 1);
    }
    strncat(resp, "]}", sizeof(resp) - strlen(resp) - 1);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_change_role(struct MHD_Connection *conn, const char *body, int target_id) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    struct user *target = find_user_by_id(target_id);
    if (!target) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Target user not found\"}");
    }

    char new_role[32] = {0};
    extract_json_string(body, "role", new_role, sizeof(new_role));

    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"message\":\"Role updated\",\"user_id\":%d,"
             "\"old_role\":\"%s\",\"new_role\":\"%s\"}",
             target_id, target->role, new_role);

    strncpy(target->role, new_role, sizeof(target->role) - 1);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_deactivate_user(struct MHD_Connection *conn, int target_id) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    struct user *caller = find_user_by_id(uid);
    if (!caller || strcmp(caller->role, "admin") != 0) {
        return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Admin access required\"}");
    }

    struct user *target = find_user_by_id(target_id);
    if (!target) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Target user not found\"}");
    }

    target->active = 0;
    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"message\":\"User deactivated\",\"user_id\":%d}", target_id);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_create_transaction(struct MHD_Connection *conn, const char *body) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    char recipient[128] = {0}, description[256] = {0};
    extract_json_string(body, "recipient", recipient, sizeof(recipient));
    extract_json_string(body, "description", description, sizeof(description));
    double amount = extract_json_number(body, "amount");

    if (strlen(recipient) == 0) {
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Recipient required\"}");
    }

    if (transaction_count >= MAX_TRANSACTIONS) {
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Transaction limit reached\"}");
    }

    struct transaction *tx = &transactions[transaction_count++];
    tx->id = transaction_count;
    tx->user_id = uid;
    tx->amount = amount;
    strncpy(tx->recipient, recipient, sizeof(tx->recipient) - 1);
    strncpy(tx->description, description, sizeof(tx->description) - 1);
    tx->timestamp = time(NULL);
    strncpy(tx->status, "completed", sizeof(tx->status) - 1);

    char resp[512];
    snprintf(resp, sizeof(resp),
             "{\"message\":\"Transaction completed\",\"transaction\":"
             "{\"id\":%d,\"user_id\":%d,\"amount\":%.2f,"
             "\"recipient\":\"%s\",\"status\":\"completed\"}}",
             tx->id, tx->user_id, tx->amount, tx->recipient);
    return send_json(conn, MHD_HTTP_CREATED, resp);
}

static enum MHD_Result handle_export_data(struct MHD_Connection *conn, const char *body) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    char export_type[64] = {0};
    extract_json_string(body, "type", export_type, sizeof(export_type));

    if (strcmp(export_type, "users") == 0) {
        char resp[4096] = "{\"export\":[";
        for (int i = 0; i < user_count; i++) {
            char entry[512];
            snprintf(entry, sizeof(entry),
                     "%s{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\","
                     "\"password\":\"%s\",\"api_key\":\"%s\",\"role\":\"%s\"}",
                     i > 0 ? "," : "",
                     users[i].id, users[i].username, users[i].email,
                     users[i].password, users[i].api_key, users[i].role);
            strncat(resp, entry, sizeof(resp) - strlen(resp) - 1);
        }
        strncat(resp, "]}", sizeof(resp) - strlen(resp) - 1);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    if (strcmp(export_type, "transactions") == 0) {
        char resp[8192] = "{\"export\":[";
        for (int i = 0; i < transaction_count; i++) {
            char entry[512];
            snprintf(entry, sizeof(entry),
                     "%s{\"id\":%d,\"user_id\":%d,\"amount\":%.2f,"
                     "\"recipient\":\"%s\",\"status\":\"%s\"}",
                     i > 0 ? "," : "",
                     transactions[i].id, transactions[i].user_id,
                     transactions[i].amount, transactions[i].recipient,
                     transactions[i].status);
            strncat(resp, entry, sizeof(resp) - strlen(resp) - 1);
        }
        strncat(resp, "]}", sizeof(resp) - strlen(resp) - 1);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Unknown export type\"}");
}

static enum MHD_Result handle_regenerate_api_key(struct MHD_Connection *conn) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    struct user *u = find_user_by_id(uid);
    if (!u) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
    }

    char old_key[64];
    strncpy(old_key, u->api_key, sizeof(old_key) - 1);
    old_key[sizeof(old_key) - 1] = '\0';

    char raw[256];
    snprintf(raw, sizeof(raw), "%s%ld", u->username, (long)time(NULL));
    char hash[65];
    simple_hash(raw, hash, sizeof(hash));
    snprintf(u->api_key, sizeof(u->api_key), "ak-%s", hash);

    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"message\":\"API key regenerated\",\"old_key\":\"%s\",\"new_key\":\"%s\"}",
             old_key, u->api_key);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_toggle_mfa(struct MHD_Connection *conn, const char *body) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    struct user *u = find_user_by_id(uid);
    if (!u) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
    }

    char enabled_str[16] = {0};
    extract_json_string(body, "enabled", enabled_str, sizeof(enabled_str));
    int enabled = (strcmp(enabled_str, "true") == 0) ? 1 : 0;

    const char *p = strstr(body, "\"enabled\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            while (*p == ' ') p++;
            if (strncmp(p, "true", 4) == 0) enabled = 1;
            else enabled = 0;
        }
    }

    u->mfa_enabled = enabled;

    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"message\":\"MFA setting updated\",\"mfa_enabled\":%s}",
             enabled ? "true" : "false");
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_validate_key(struct MHD_Connection *conn, const char *body) {
    char api_key[64] = {0};
    extract_json_string(body, "api_key", api_key, sizeof(api_key));

    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].api_key, api_key) == 0) {
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "{\"valid\":true,\"user_id\":%d,\"username\":\"%s\",\"role\":\"%s\"}",
                     users[i].id, users[i].username, users[i].role);
            return send_json(conn, MHD_HTTP_OK, resp);
        }
    }

    return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"valid\":false}");
}

static int parse_id_from_url(const char *url, const char *prefix) {
    const char *p = strstr(url, prefix);
    if (!p) return -1;
    p += strlen(prefix);
    return atoi(p);
}

struct post_data {
    char buffer[MAX_POST_SIZE];
    size_t size;
};

static enum MHD_Result handle_request(void *cls, struct MHD_Connection *conn,
                                       const char *url, const char *method,
                                       const char *version, const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {
    (void)cls; (void)version;

    if (*con_cls == NULL) {
        struct post_data *pd = calloc(1, sizeof(struct post_data));
        *con_cls = pd;
        return MHD_YES;
    }

    struct post_data *pd = *con_cls;

    if (*upload_data_size > 0) {
        size_t to_copy = *upload_data_size;
        if (pd->size + to_copy >= MAX_POST_SIZE)
            to_copy = MAX_POST_SIZE - pd->size - 1;
        memcpy(pd->buffer + pd->size, upload_data, to_copy);
        pd->size += to_copy;
        pd->buffer[pd->size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    enum MHD_Result ret;

    if (strcmp(method, "POST") == 0 && strcmp(url, "/api/login") == 0) {
        ret = handle_login(conn, pd->buffer);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/admin/users") == 0) {
        ret = handle_list_users(conn);
    } else if (strcmp(method, "PUT") == 0 && strncmp(url, "/api/admin/users/", 17) == 0 &&
               strstr(url, "/role") != NULL) {
        int target_id = parse_id_from_url(url, "/api/admin/users/");
        ret = handle_change_role(conn, pd->buffer, target_id);
    } else if (strcmp(method, "POST") == 0 && strncmp(url, "/api/admin/users/", 17) == 0 &&
               strstr(url, "/deactivate") != NULL) {
        int target_id = parse_id_from_url(url, "/api/admin/users/");
        ret = handle_deactivate_user(conn, target_id);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/transactions") == 0) {
        ret = handle_create_transaction(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/export/data") == 0) {
        ret = handle_export_data(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/settings/api-key") == 0) {
        ret = handle_regenerate_api_key(conn);
    } else if (strcmp(method, "PUT") == 0 && strcmp(url, "/api/settings/mfa") == 0) {
        ret = handle_toggle_mfa(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/validate-key") == 0) {
        ret = handle_validate_key(conn, pd->buffer);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/health") == 0) {
        ret = send_json(conn, MHD_HTTP_OK, "{\"status\":\"healthy\",\"service\":\"logging-api\"}");
    } else {
        ret = send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Not found\"}");
    }

    free(pd);
    *con_cls = NULL;
    return ret;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    init_data();

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        return 1;
    }

    printf("Logging Monitor API running on port %d\n", PORT);
    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}
