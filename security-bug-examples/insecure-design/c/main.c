#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>

#define MAX_USERS 16
#define MAX_SESSIONS 64
#define MAX_RESET_TOKENS 32
#define MAX_POST_SIZE 4096
#define PORT 9087

static const char *DB_HOST = "db.internal.acmecorp.io";
static const char *DB_USER = "appuser";
static const char *DB_PASS = "Pg_Pr0d#2024";
static const char *SMTP_HOST = "mail.internal.acmecorp.io";
static const char *SMTP_PASS = "SmtpR3lay#2024!";

struct user {
    int id;
    char username[64];
    char email[128];
    char password[128];
    char role[32];
    int active;
    int failed_attempts;
};

struct session {
    char token[65];
    int user_id;
    time_t created;
};

struct reset_token {
    char token[33];
    int user_id;
    time_t created;
};

static struct user users[MAX_USERS];
static int user_count = 0;
static struct session sessions[MAX_SESSIONS];
static int session_count = 0;
static struct reset_token reset_tokens[MAX_RESET_TOKENS];
static int reset_token_count = 0;

static void init_data(void) {
    struct user defaults[] = {
        {1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", 1, 0},
        {2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", 1, 0},
        {3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", 1, 0},
        {4, "bwilson", "bwilson@acmecorp.io", "B0b_W1ls0n", "analyst", 0, 0},
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

static struct user *find_user_by_email(const char *email) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].email, email) == 0) return &users[i];
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
        char resp[256];
        snprintf(resp, sizeof(resp),
                 "{\"error\":\"No account found for username '%s'\"}", username);
        return send_json(conn, MHD_HTTP_NOT_FOUND, resp);
    }

    if (!u->active) {
        char resp[256];
        snprintf(resp, sizeof(resp),
                 "{\"error\":\"Account '%s' is deactivated. Contact admin@acmecorp.io.\"}", username);
        return send_json(conn, MHD_HTTP_FORBIDDEN, resp);
    }

    if (strcmp(u->password, password) == 0) {
        u->failed_attempts = 0;
        const char *token = create_session(u->id);
        char resp[256];
        snprintf(resp, sizeof(resp),
                 "{\"token\":\"%s\",\"user_id\":%d,\"role\":\"%s\"}", token, u->id, u->role);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    u->failed_attempts++;
    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"error\":\"Incorrect password\",\"attempts\":%d}", u->failed_attempts);
    return send_json(conn, MHD_HTTP_UNAUTHORIZED, resp);
}

static enum MHD_Result handle_register(struct MHD_Connection *conn, const char *body) {
    char username[64] = {0}, email[128] = {0}, password[128] = {0};
    extract_json_string(body, "username", username, sizeof(username));
    extract_json_string(body, "email", email, sizeof(email));
    extract_json_string(body, "password", password, sizeof(password));

    if (strlen(username) == 0 || strlen(email) == 0 || strlen(password) == 0) {
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"All fields required\"}");
    }

    if (find_user_by_username(username)) {
        char resp[256];
        snprintf(resp, sizeof(resp),
                 "{\"error\":\"Username '%s' is already taken\"}", username);
        return send_json(conn, MHD_HTTP_CONFLICT, resp);
    }

    if (find_user_by_email(email)) {
        char resp[256];
        snprintf(resp, sizeof(resp),
                 "{\"error\":\"Email '%s' is already registered\"}", email);
        return send_json(conn, MHD_HTTP_CONFLICT, resp);
    }

    if (user_count >= MAX_USERS) {
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"User limit reached\"}");
    }

    struct user *nu = &users[user_count++];
    nu->id = users[user_count - 2].id + 1;
    strncpy(nu->username, username, sizeof(nu->username) - 1);
    strncpy(nu->email, email, sizeof(nu->email) - 1);
    strncpy(nu->password, password, sizeof(nu->password) - 1);
    strncpy(nu->role, "viewer", sizeof(nu->role) - 1);
    nu->active = 1;
    nu->failed_attempts = 0;

    char resp[128];
    snprintf(resp, sizeof(resp), "{\"message\":\"User registered\",\"user_id\":%d}", nu->id);
    return send_json(conn, MHD_HTTP_CREATED, resp);
}

static enum MHD_Result handle_password_reset(struct MHD_Connection *conn, const char *body) {
    char email[128] = {0};
    extract_json_string(body, "email", email, sizeof(email));

    struct user *u = find_user_by_email(email);
    if (!u) {
        char resp[256];
        snprintf(resp, sizeof(resp),
                 "{\"error\":\"No account associated with '%s'\"}", email);
        return send_json(conn, MHD_HTTP_NOT_FOUND, resp);
    }

    if (reset_token_count >= MAX_RESET_TOKENS) {
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Token limit reached\"}");
    }

    struct reset_token *rt = &reset_tokens[reset_token_count++];
    char raw[256];
    snprintf(raw, sizeof(raw), "%s%ld", email, (long)time(NULL));
    simple_hash(raw, rt->token, sizeof(rt->token));
    rt->user_id = u->id;
    rt->created = time(NULL);

    char resp[512];
    snprintf(resp, sizeof(resp),
             "{\"message\":\"Password reset link sent\",\"token\":\"%s\",\"smtp_server\":\"%s\"}",
             rt->token, SMTP_HOST);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_password_reset_confirm(struct MHD_Connection *conn, const char *body) {
    char token[33] = {0}, new_password[128] = {0};
    extract_json_string(body, "token", token, sizeof(token));
    extract_json_string(body, "new_password", new_password, sizeof(new_password));

    for (int i = 0; i < reset_token_count; i++) {
        if (strcmp(reset_tokens[i].token, token) == 0) {
            struct user *u = find_user_by_id(reset_tokens[i].user_id);
            if (u) {
                strncpy(u->password, new_password, sizeof(u->password) - 1);
                memmove(&reset_tokens[i], &reset_tokens[i + 1],
                        (reset_token_count - i - 1) * sizeof(struct reset_token));
                reset_token_count--;
                return send_json(conn, MHD_HTTP_OK, "{\"message\":\"Password updated successfully\"}");
            }
            return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
        }
    }

    return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid or expired token\"}");
}

static enum MHD_Result handle_change_password(struct MHD_Connection *conn, const char *body) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    char new_password[128] = {0};
    extract_json_string(body, "new_password", new_password, sizeof(new_password));

    struct user *u = find_user_by_id(uid);
    if (!u) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
    }

    strncpy(u->password, new_password, sizeof(u->password) - 1);
    return send_json(conn, MHD_HTTP_OK, "{\"message\":\"Password updated\"}");
}

static enum MHD_Result handle_get_config(struct MHD_Connection *conn) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    struct user *u = find_user_by_id(uid);
    if (!u || strcmp(u->role, "admin") != 0) {
        return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Admin access required\"}");
    }

    char resp[1024];
    snprintf(resp, sizeof(resp),
             "{\"database_host\":\"%s\",\"database_user\":\"%s\",\"database_password\":\"%s\","
             "\"smtp_host\":\"%s\",\"smtp_password\":\"%s\","
             "\"session_count\":%d,\"user_count\":%d}",
             DB_HOST, DB_USER, DB_PASS, SMTP_HOST, SMTP_PASS,
             session_count, user_count);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_debug_user(struct MHD_Connection *conn, int user_id) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    struct user *u = find_user_by_id(user_id);
    if (!u) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
    }

    char resp[512];
    snprintf(resp, sizeof(resp),
             "{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\",\"password\":\"%s\","
             "\"role\":\"%s\",\"active\":%s,\"failed_attempts\":%d}",
             u->id, u->username, u->email, u->password,
             u->role, u->active ? "true" : "false", u->failed_attempts);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_report(struct MHD_Connection *conn, const char *body) {
    int uid = get_session_user(conn);
    if (uid < 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    char report_type[64] = {0};
    extract_json_string(body, "type", report_type, sizeof(report_type));

    char resp[1024];
    snprintf(resp, sizeof(resp),
             "{\"error\":\"Report generation failed\","
             "\"details\":\"Could not connect to database at %s as user '%s' with password '%s'\","
             "\"report_type\":\"%s\"}",
             DB_HOST, DB_USER, DB_PASS, report_type);
    return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
}

struct post_data {
    char buffer[MAX_POST_SIZE];
    size_t size;
};

static int parse_user_id_from_url(const char *url) {
    const char *p = strrchr(url, '/');
    if (p) return atoi(p + 1);
    return -1;
}

static enum MHD_Result handle_request(void *cls, struct MHD_Connection *conn,
                                       const char *url, const char *method,
                                       const char *version, const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {
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
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/register") == 0) {
        ret = handle_register(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/password-reset") == 0) {
        ret = handle_password_reset(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/password-reset/confirm") == 0) {
        ret = handle_password_reset_confirm(conn, pd->buffer);
    } else if (strcmp(method, "PUT") == 0 && strcmp(url, "/api/users/me/password") == 0) {
        ret = handle_change_password(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/reports/generate") == 0) {
        ret = handle_report(conn, pd->buffer);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/config") == 0) {
        ret = handle_get_config(conn);
    } else if (strcmp(method, "GET") == 0 && strncmp(url, "/api/debug/user/", 16) == 0) {
        int target_id = parse_user_id_from_url(url);
        ret = handle_debug_user(conn, target_id);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/health") == 0) {
        ret = send_json(conn, MHD_HTTP_OK, "{\"status\":\"healthy\",\"service\":\"design-api\"}");
    } else {
        ret = send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Not found\"}");
    }

    free(pd);
    *con_cls = NULL;
    return ret;
}

int main(int argc, char *argv[]) {
    init_data();

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        return 1;
    }

    printf("Design Service API running on port %d\n", PORT);
    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}
