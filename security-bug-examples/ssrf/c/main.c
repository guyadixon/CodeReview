#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>
#include <curl/curl.h>

#define MAX_USERS 8
#define MAX_SESSIONS 64
#define MAX_WEBHOOKS 64
#define MAX_POST_SIZE 8192
#define PORT 9010

struct user {
    int id;
    char username[64];
    char email[128];
    char password[128];
    char role[32];
    int active;
    char api_key[64];
};

struct session {
    char token[65];
    int user_id;
    time_t created;
};

struct webhook {
    char id[16];
    char callback_url[512];
    char event_type[64];
    int user_id;
    time_t created;
};

static struct user users[MAX_USERS];
static int user_count = 0;
static struct session sessions[MAX_SESSIONS];
static int session_count = 0;
static struct webhook webhooks[MAX_WEBHOOKS];
static int webhook_count = 0;

static void init_data(void) {
    struct user defaults[] = {
        {1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", 1, "ak-admin-x7k9m2"},
        {2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", 1, "ak-jdoe-p3q8r1"},
        {3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", 1, "ak-asmith-w5t6y4"},
    };
    user_count = 3;
    for (int i = 0; i < user_count; i++) {
        users[i] = defaults[i];
    }
}

static void simple_hash(const char *input, char *output, size_t out_sz) {
    unsigned long h = 5381;
    for (const char *p = input; *p; p++) {
        h = ((h << 5) + h) + (unsigned char)*p;
    }
    snprintf(output, out_sz, "%016lx", h);
}

static const char *extract_json_string(const char *json, const char *key, char *buf, size_t buf_sz) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(json, pattern);
    if (!pos) return NULL;
    pos = strchr(pos + strlen(pattern), ':');
    if (!pos) return NULL;
    pos++;
    while (*pos == ' ' || *pos == '\t') pos++;
    if (*pos == '"') {
        pos++;
        size_t i = 0;
        while (*pos && *pos != '"' && i < buf_sz - 1) {
            buf[i++] = *pos++;
        }
        buf[i] = '\0';
        return buf;
    }
    return NULL;
}

static int find_session(const char *token) {
    for (int i = 0; i < session_count; i++) {
        if (strcmp(sessions[i].token, token) == 0) return i;
    }
    return -1;
}

static int get_session_user(struct MHD_Connection *conn) {
    const char *auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
    if (!auth || strncmp(auth, "Bearer ", 7) != 0) return -1;
    int idx = find_session(auth + 7);
    if (idx < 0) return -1;
    return sessions[idx].user_id;
}

struct curl_buffer {
    char *data;
    size_t size;
    size_t capacity;
};

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    struct curl_buffer *buf = (struct curl_buffer *)userp;
    if (buf->size + total >= buf->capacity) {
        size_t new_cap = buf->capacity * 2 + total;
        char *tmp = realloc(buf->data, new_cap);
        if (!tmp) return 0;
        buf->data = tmp;
        buf->capacity = new_cap;
    }
    memcpy(buf->data + buf->size, contents, total);
    buf->size += total;
    buf->data[buf->size] = '\0';
    return total;
}

static int fetch_remote(const char *url, struct curl_buffer *result) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    result->data = malloc(4096);
    result->size = 0;
    result->capacity = 4096;
    result->data[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, result);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return (res == CURLE_OK) ? 0 : -1;
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

    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 && strcmp(users[i].password, password) == 0) {
            if (!users[i].active) {
                return send_json(conn, 403, "{\"error\":\"Account disabled\"}");
            }
            char raw[128];
            snprintf(raw, sizeof(raw), "%d-%ld", users[i].id, (long)time(NULL));
            char token[65];
            simple_hash(raw, token, sizeof(token));
            if (session_count < MAX_SESSIONS) {
                strncpy(sessions[session_count].token, token, 64);
                sessions[session_count].user_id = users[i].id;
                sessions[session_count].created = time(NULL);
                session_count++;
            }
            char resp_buf[256];
            snprintf(resp_buf, sizeof(resp_buf),
                     "{\"token\":\"%s\",\"user_id\":%d,\"role\":\"%s\"}",
                     token, users[i].id, users[i].role);
            return send_json(conn, 200, resp_buf);
        }
    }
    return send_json(conn, 401, "{\"error\":\"Invalid credentials\"}");
}

static enum MHD_Result handle_fetch_url(struct MHD_Connection *conn, const char *body) {
    int uid = get_session_user(conn);
    if (uid < 0) return send_json(conn, 401, "{\"error\":\"Authentication required\"}");

    char url[512] = {0};
    extract_json_string(body, "url", url, sizeof(url));
    if (url[0] == '\0') return send_json(conn, 400, "{\"error\":\"URL parameter required\"}");

    struct curl_buffer result;
    if (fetch_remote(url, &result) != 0) {
        free(result.data);
        return send_json(conn, 502, "{\"error\":\"Failed to fetch URL\"}");
    }

    char *resp_buf = malloc(result.size + 256);
    snprintf(resp_buf, result.size + 256,
             "{\"status\":200,\"content_length\":%zu,\"body\":\"%.*s\"}",
             result.size, (int)(result.size > 5000 ? 5000 : result.size), result.data);
    enum MHD_Result ret = send_json(conn, 200, resp_buf);
    free(result.data);
    free(resp_buf);
    return ret;
}

static enum MHD_Result handle_preview(struct MHD_Connection *conn) {
    int uid = get_session_user(conn);
    if (uid < 0) return send_json(conn, 401, "{\"error\":\"Authentication required\"}");

    const char *target = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "target");
    if (!target || target[0] == '\0') {
        return send_json(conn, 400, "{\"error\":\"target parameter required\"}");
    }

    if (strstr(target, "localhost") != NULL || strstr(target, "127.0.0.1") != NULL) {
        return send_json(conn, 403, "{\"error\":\"Blocked host\"}");
    }

    struct curl_buffer result;
    if (fetch_remote(target, &result) != 0) {
        free(result.data);
        return send_json(conn, 502, "{\"error\":\"Failed to fetch URL\"}");
    }

    char *resp_buf = malloc(result.size + 256);
    snprintf(resp_buf, result.size + 256,
             "{\"url\":\"%s\",\"preview\":\"%.*s\"}",
             target, (int)(result.size > 2000 ? 2000 : result.size), result.data);
    enum MHD_Result ret = send_json(conn, 200, resp_buf);
    free(result.data);
    free(resp_buf);
    return ret;
}

static enum MHD_Result handle_register_webhook(struct MHD_Connection *conn, const char *body) {
    int uid = get_session_user(conn);
    if (uid < 0) return send_json(conn, 401, "{\"error\":\"Authentication required\"}");

    char callback_url[512] = {0}, event_type[64] = {0};
    extract_json_string(body, "callback_url", callback_url, sizeof(callback_url));
    extract_json_string(body, "event_type", event_type, sizeof(event_type));

    if (callback_url[0] == '\0') return send_json(conn, 400, "{\"error\":\"callback_url required\"}");
    if (strncmp(callback_url, "http://", 7) != 0 && strncmp(callback_url, "https://", 8) != 0) {
        return send_json(conn, 400, "{\"error\":\"Only HTTP(S) callbacks supported\"}");
    }
    if (event_type[0] == '\0') strncpy(event_type, "default", sizeof(event_type));

    if (webhook_count < MAX_WEBHOOKS) {
        char raw[256];
        snprintf(raw, sizeof(raw), "%s%ld", callback_url, (long)time(NULL));
        simple_hash(raw, webhooks[webhook_count].id, sizeof(webhooks[webhook_count].id));
        webhooks[webhook_count].id[12] = '\0';
        strncpy(webhooks[webhook_count].callback_url, callback_url, 511);
        strncpy(webhooks[webhook_count].event_type, event_type, 63);
        webhooks[webhook_count].user_id = uid;
        webhooks[webhook_count].created = time(NULL);

        char resp_buf[256];
        snprintf(resp_buf, sizeof(resp_buf),
                 "{\"message\":\"Webhook registered\",\"webhook_id\":\"%s\"}",
                 webhooks[webhook_count].id);
        webhook_count++;
        return send_json(conn, 201, resp_buf);
    }
    return send_json(conn, 500, "{\"error\":\"Webhook storage full\"}");
}

static enum MHD_Result handle_test_webhook(struct MHD_Connection *conn, const char *wh_id) {
    int uid = get_session_user(conn);
    if (uid < 0) return send_json(conn, 401, "{\"error\":\"Authentication required\"}");

    int idx = -1;
    for (int i = 0; i < webhook_count; i++) {
        if (strcmp(webhooks[i].id, wh_id) == 0) { idx = i; break; }
    }
    if (idx < 0) return send_json(conn, 404, "{\"error\":\"Webhook not found\"}");

    CURL *curl = curl_easy_init();
    if (!curl) return send_json(conn, 500, "{\"error\":\"Internal error\"}");

    char payload[128];
    snprintf(payload, sizeof(payload), "{\"event\":\"test\",\"timestamp\":%ld}", (long)time(NULL));

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, webhooks[idx].callback_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK) {
        return send_json(conn, 200, "{\"message\":\"Webhook delivered\"}");
    }
    return send_json(conn, 502, "{\"error\":\"Delivery failed\"}");
}

static enum MHD_Result handle_import_config(struct MHD_Connection *conn, const char *body) {
    int uid = get_session_user(conn);
    if (uid < 0) return send_json(conn, 401, "{\"error\":\"Authentication required\"}");

    char config_url[512] = {0};
    extract_json_string(body, "config_url", config_url, sizeof(config_url));
    if (config_url[0] == '\0') return send_json(conn, 400, "{\"error\":\"config_url required\"}");

    if (strncmp(config_url, "http://", 7) != 0 && strncmp(config_url, "https://", 8) != 0) {
        return send_json(conn, 400, "{\"error\":\"Only HTTP(S) URLs supported\"}");
    }

    if (strstr(config_url, "169.254") != NULL) {
        return send_json(conn, 403, "{\"error\":\"Metadata endpoints not allowed\"}");
    }

    struct curl_buffer result;
    if (fetch_remote(config_url, &result) != 0) {
        free(result.data);
        return send_json(conn, 502, "{\"error\":\"Failed to fetch config\"}");
    }

    char *resp_buf = malloc(result.size + 256);
    snprintf(resp_buf, result.size + 256,
             "{\"message\":\"Configuration imported\",\"config\":\"%.*s\"}",
             (int)(result.size > 5000 ? 5000 : result.size), result.data);
    enum MHD_Result ret = send_json(conn, 200, resp_buf);
    free(result.data);
    free(resp_buf);
    return ret;
}

static enum MHD_Result handle_proxy(struct MHD_Connection *conn) {
    int uid = get_session_user(conn);
    if (uid < 0) return send_json(conn, 401, "{\"error\":\"Authentication required\"}");

    const char *service = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "service");
    const char *path = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "path");
    const char *base_url = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "base_url");

    if (!path) path = "/";

    const char *resolved_base = NULL;
    if (service) {
        if (strcmp(service, "analytics") == 0) resolved_base = "http://analytics-service:8081";
        else if (strcmp(service, "billing") == 0) resolved_base = "http://billing-service:8082";
        else if (strcmp(service, "notifications") == 0) resolved_base = "http://notifications-service:8083";
    }

    if (!resolved_base) {
        if (base_url && base_url[0] != '\0') {
            resolved_base = base_url;
        } else {
            return send_json(conn, 400, "{\"error\":\"Unknown service\"}");
        }
    }

    char full_url[1024];
    snprintf(full_url, sizeof(full_url), "%s%s", resolved_base, path);

    struct curl_buffer result;
    if (fetch_remote(full_url, &result) != 0) {
        free(result.data);
        return send_json(conn, 502, "{\"error\":\"Proxy request failed\"}");
    }

    char *resp_buf = malloc(result.size + 256);
    snprintf(resp_buf, result.size + 256,
             "{\"status\":200,\"body\":\"%.*s\"}",
             (int)(result.size > 5000 ? 5000 : result.size), result.data);
    enum MHD_Result ret = send_json(conn, 200, resp_buf);
    free(result.data);
    free(resp_buf);
    return ret;
}

static const char *extract_webhook_id(const char *url) {
    const char *prefix = "/api/webhooks/";
    const char *pos = strstr(url, prefix);
    if (!pos) return NULL;
    pos += strlen(prefix);
    static char id_buf[16];
    size_t i = 0;
    while (*pos && *pos != '/' && i < sizeof(id_buf) - 1) {
        id_buf[i++] = *pos++;
    }
    id_buf[i] = '\0';
    if (strstr(pos, "/test")) return id_buf;
    return NULL;
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

    struct post_data *pd = (struct post_data *)*con_cls;

    if (*upload_data_size > 0) {
        size_t to_copy = *upload_data_size;
        if (pd->size + to_copy >= MAX_POST_SIZE) to_copy = MAX_POST_SIZE - pd->size - 1;
        memcpy(pd->buffer + pd->size, upload_data, to_copy);
        pd->size += to_copy;
        pd->buffer[pd->size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    enum MHD_Result ret;

    if (strcmp(method, "POST") == 0 && strcmp(url, "/api/login") == 0) {
        ret = handle_login(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/fetch-url") == 0) {
        ret = handle_fetch_url(conn, pd->buffer);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/preview") == 0) {
        ret = handle_preview(conn);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/webhooks") == 0) {
        ret = handle_register_webhook(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strstr(url, "/api/webhooks/") && strstr(url, "/test")) {
        const char *wh_id = extract_webhook_id(url);
        if (wh_id) {
            ret = handle_test_webhook(conn, wh_id);
        } else {
            ret = send_json(conn, 404, "{\"error\":\"Not found\"}");
        }
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/integrations/import") == 0) {
        ret = handle_import_config(conn, pd->buffer);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/proxy") == 0) {
        ret = handle_proxy(conn);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/health") == 0) {
        ret = send_json(conn, 200, "{\"status\":\"healthy\",\"service\":\"gateway-api\"}");
    } else {
        ret = send_json(conn, 404, "{\"error\":\"Not found\"}");
    }

    free(pd);
    *con_cls = NULL;
    return ret;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    init_data();
    curl_global_init(CURL_GLOBAL_DEFAULT);

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
        &handle_request, NULL, MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    printf("Gateway API running on port %d\n", PORT);
    getchar();
    MHD_stop_daemon(daemon);
    curl_global_cleanup();
    return 0;
}
