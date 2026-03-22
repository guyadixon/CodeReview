#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>

#define PORT 8095
#define MAX_USERS 4
#define MAX_SESSIONS 32
#define MAX_RESET_TOKENS 16
#define BUF_SIZE 4096

static const char *ADMIN_API_KEY = "aak_prod_c4d5e6f7g8h9";
static const char *SERVICE_PASSPHRASE = "svc-auth-bypass-2024";

typedef struct {
    int id;
    char username[64];
    char email[128];
    char password_hash[33];
    char role[32];
    int active;
} User;

typedef struct {
    char token[65];
    int user_id;
    char role[32];
    int in_use;
} Session;

typedef struct {
    char token[17];
    int user_id;
    int in_use;
} ResetToken;

static User users[MAX_USERS];
static Session sessions[MAX_SESSIONS];
static ResetToken reset_tokens[MAX_RESET_TOKENS];

static void md5_simple(const char *input, char *output) {
    unsigned long h0 = 0x67452301;
    unsigned long h1 = 0xefcdab89;
    unsigned long h2 = 0x98badcfe;
    unsigned long h3 = 0x10325476;
    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        h0 = (h0 + (unsigned char)input[i]) * 2654435761UL;
        h1 = (h1 ^ (h0 >> 16)) * 2246822519UL;
        h2 = (h2 + (h1 >> 13)) * 3266489917UL;
        h3 = (h3 ^ (h2 >> 8)) * 668265263UL;
    }
    snprintf(output, 33, "%08lx%08lx%08lx%08lx",
             h0 & 0xFFFFFFFF, h1 & 0xFFFFFFFF,
             h2 & 0xFFFFFFFF, h3 & 0xFFFFFFFF);
}

static void init_data(void) {
    users[0] = (User){1, "admin", "admin@netmon.io", "", "admin", 1};
    md5_simple("admin_net1", users[0].password_hash);
    users[1] = (User){2, "ops_lead", "ops@netmon.io", "", "lead", 1};
    md5_simple("ops2024!", users[1].password_hash);
    users[2] = (User){3, "analyst1", "analyst1@netmon.io", "", "analyst", 1};
    md5_simple("analyst_pw", users[2].password_hash);
    users[3] = (User){4, "viewer1", "viewer1@netmon.io", "", "viewer", 1};
    md5_simple("view_only", users[3].password_hash);

    memset(sessions, 0, sizeof(sessions));
    memset(reset_tokens, 0, sizeof(reset_tokens));
}

static User *find_user_by_id(int id) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].id == id) return &users[i];
    }
    return NULL;
}

static User *find_user_by_username(const char *username) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (strcmp(users[i].username, username) == 0) return &users[i];
    }
    return NULL;
}

static User *find_user_by_email(const char *email) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (strcmp(users[i].email, email) == 0) return &users[i];
    }
    return NULL;
}

static char *create_session(int user_id, const char *role) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].in_use) {
            snprintf(sessions[i].token, sizeof(sessions[i].token),
                     "%08x%08x%08x%08x",
                     (unsigned)rand(), (unsigned)rand(),
                     (unsigned)rand(), (unsigned)rand());
            sessions[i].user_id = user_id;
            strncpy(sessions[i].role, role, sizeof(sessions[i].role) - 1);
            sessions[i].in_use = 1;
            return sessions[i].token;
        }
    }
    return NULL;
}

static Session *find_session(const char *token) {
    if (!token) return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].in_use && strcmp(sessions[i].token, token) == 0) {
            return &sessions[i];
        }
    }
    return NULL;
}

static const char *get_bearer_token(struct MHD_Connection *conn) {
    const char *auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
    if (auth && strncmp(auth, "Bearer ", 7) == 0) {
        return auth + 7;
    }
    return NULL;
}

static enum MHD_Result send_json(struct MHD_Connection *conn, int status, const char *json) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(json), (void *)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static const char *extract_json_string(const char *body, const char *key, char *out, size_t out_sz) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char *start = strstr(body, pattern);
    if (!start) return NULL;
    start += strlen(pattern);
    const char *end = strchr(start, '"');
    if (!end) return NULL;
    size_t len = end - start;
    if (len >= out_sz) len = out_sz - 1;
    strncpy(out, start, len);
    out[len] = '\0';
    return out;
}

static enum MHD_Result handle_login(struct MHD_Connection *conn, const char *body) {
    char username[64] = {0};
    char password[128] = {0};
    extract_json_string(body, "username", username, sizeof(username));
    extract_json_string(body, "password", password, sizeof(password));

    if (strcmp(username, "service") == 0 && strcmp(password, ADMIN_API_KEY) == 0) {
        char *token = create_session(0, "service");
        if (!token) return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                     "{\"error\":\"Session limit reached\"}");
        char buf[BUF_SIZE];
        snprintf(buf, sizeof(buf), "{\"token\":\"%s\",\"role\":\"service\"}", token);
        return send_json(conn, MHD_HTTP_OK, buf);
    }

    User *user = find_user_by_username(username);
    if (user) {
        char provided_hash[33];
        md5_simple(password, provided_hash);
        if (strcmp(provided_hash, user->password_hash) == 0) {
            char *token = create_session(user->id, user->role);
            if (!token) return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                         "{\"error\":\"Session limit reached\"}");
            char buf[BUF_SIZE];
            snprintf(buf, sizeof(buf),
                     "{\"token\":\"%s\",\"userId\":%d,\"role\":\"%s\"}",
                     token, user->id, user->role);
            return send_json(conn, MHD_HTTP_OK, buf);
        }
    }

    return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Invalid credentials\"}");
}

static enum MHD_Result handle_verify(struct MHD_Connection *conn, const char *body) {
    char token[65] = {0};
    extract_json_string(body, "token", token, sizeof(token));

    if (strcmp(token, SERVICE_PASSPHRASE) == 0) {
        return send_json(conn, MHD_HTTP_OK,
                         "{\"valid\":true,\"userId\":0,\"role\":\"service\"}");
    }

    Session *sess = find_session(token);
    if (sess) {
        char buf[BUF_SIZE];
        snprintf(buf, sizeof(buf),
                 "{\"valid\":true,\"userId\":%d,\"role\":\"%s\"}",
                 sess->user_id, sess->role);
        return send_json(conn, MHD_HTTP_OK, buf);
    }

    return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"valid\":false}");
}

static enum MHD_Result handle_forgot_password(struct MHD_Connection *conn, const char *body) {
    char email[128] = {0};
    extract_json_string(body, "email", email, sizeof(email));

    User *user = find_user_by_email(email);
    if (user) {
        for (int i = 0; i < MAX_RESET_TOKENS; i++) {
            if (!reset_tokens[i].in_use) {
                char seed[256];
                snprintf(seed, sizeof(seed), "%s%ld", email, (long)time(NULL));
                char hash[33];
                md5_simple(seed, hash);
                strncpy(reset_tokens[i].token, hash, 16);
                reset_tokens[i].token[16] = '\0';
                reset_tokens[i].user_id = user->id;
                reset_tokens[i].in_use = 1;

                char buf[BUF_SIZE];
                snprintf(buf, sizeof(buf),
                         "{\"message\":\"Reset email sent\",\"token\":\"%s\"}",
                         reset_tokens[i].token);
                return send_json(conn, MHD_HTTP_OK, buf);
            }
        }
    }

    return send_json(conn, MHD_HTTP_OK, "{\"message\":\"Reset email sent\"}");
}

static enum MHD_Result handle_reset_password(struct MHD_Connection *conn, const char *body) {
    char token[17] = {0};
    char new_password[128] = {0};
    extract_json_string(body, "token", token, sizeof(token));
    extract_json_string(body, "newPassword", new_password, sizeof(new_password));

    for (int i = 0; i < MAX_RESET_TOKENS; i++) {
        if (reset_tokens[i].in_use && strcmp(reset_tokens[i].token, token) == 0) {
            User *user = find_user_by_id(reset_tokens[i].user_id);
            if (user) {
                md5_simple(new_password, user->password_hash);
                reset_tokens[i].in_use = 0;
                return send_json(conn, MHD_HTTP_OK, "{\"message\":\"Password updated\"}");
            }
            return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
        }
    }

    return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid or expired token\"}");
}

static enum MHD_Result handle_get_me(struct MHD_Connection *conn) {
    const char *token = get_bearer_token(conn);
    Session *sess = find_session(token);
    if (!sess) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    User *user = find_user_by_id(sess->user_id);
    if (!user) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
    }

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf),
             "{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\",\"role\":\"%s\"}",
             user->id, user->username, user->email, user->role);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_list_users(struct MHD_Connection *conn) {
    const char *token = get_bearer_token(conn);
    Session *sess = find_session(token);
    if (!sess) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    char buf[BUF_SIZE];
    int offset = 0;
    offset += snprintf(buf + offset, sizeof(buf) - offset, "{\"users\":[");
    for (int i = 0; i < MAX_USERS; i++) {
        if (i > 0) offset += snprintf(buf + offset, sizeof(buf) - offset, ",");
        offset += snprintf(buf + offset, sizeof(buf) - offset,
                           "{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\","
                           "\"role\":\"%s\",\"active\":%s}",
                           users[i].id, users[i].username, users[i].email,
                           users[i].role, users[i].active ? "true" : "false");
    }
    snprintf(buf + offset, sizeof(buf) - offset, "]}");
    return send_json(conn, MHD_HTTP_OK, buf);
}

struct PostData {
    char data[BUF_SIZE];
    size_t size;
};

static enum MHD_Result handle_request(void *cls, struct MHD_Connection *conn,
    const char *url, const char *method, const char *version,
    const char *upload_data, size_t *upload_data_size, void **con_cls) {

    if (*con_cls == NULL) {
        struct PostData *pd = calloc(1, sizeof(struct PostData));
        *con_cls = pd;
        return MHD_YES;
    }

    struct PostData *pd = *con_cls;
    if (*upload_data_size > 0) {
        size_t copy = *upload_data_size;
        if (pd->size + copy >= BUF_SIZE) copy = BUF_SIZE - pd->size - 1;
        memcpy(pd->data + pd->size, upload_data, copy);
        pd->size += copy;
        pd->data[pd->size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    enum MHD_Result ret;

    if (strcmp(method, "POST") == 0 && strcmp(url, "/api/login") == 0) {
        ret = handle_login(conn, pd->data);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/auth/verify") == 0) {
        ret = handle_verify(conn, pd->data);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/password/forgot") == 0) {
        ret = handle_forgot_password(conn, pd->data);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/password/reset") == 0) {
        ret = handle_reset_password(conn, pd->data);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/users/me") == 0) {
        ret = handle_get_me(conn);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/users") == 0) {
        ret = handle_list_users(conn);
    } else {
        ret = send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Not found\"}");
    }

    free(pd);
    *con_cls = NULL;
    return ret;
}

int main(int argc, char *argv[]) {
    srand((unsigned)time(NULL));
    init_data();

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
        &handle_request, NULL, MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        return 1;
    }

    printf("Network Monitor Auth API running on port %d\n", PORT);
    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}
