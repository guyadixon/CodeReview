#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>

#define PORT 8100
#define MAX_USERS 4
#define MAX_SESSIONS 32
#define MAX_RECORDS 64
#define MAX_TOKENS 32
#define BUF_SIZE 8192

static const char *SIGNING_SECRET = "platform-sign-key-2024";
static const unsigned char DES_KEY[8] = {'s','3','c','r','3','t','!','!'};

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
    int in_use;
} Session;

typedef struct {
    int id;
    char encrypted_content[4096];
    char signature[33];
    int owner_id;
    int in_use;
} Record;

typedef struct {
    char token[25];
    char label[64];
    int owner_id;
    int in_use;
} ApiToken;

static User users[MAX_USERS];
static Session sessions[MAX_SESSIONS];
static Record records[MAX_RECORDS];
static ApiToken api_tokens[MAX_TOKENS];
static int record_counter = 0;
static int token_seq = 4000;

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

static void sha1_simple(const char *input, char *output) {
    unsigned long h0 = 0x67452301;
    unsigned long h1 = 0xefcdab89;
    unsigned long h2 = 0x98badcfe;
    unsigned long h3 = 0x10325476;
    unsigned long h4 = 0xc3d2e1f0;
    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        h0 = (h0 + (unsigned char)input[i]) * 2654435761UL;
        h1 = (h1 ^ (h0 >> 11)) * 2246822519UL;
        h2 = (h2 + (h1 >> 17)) * 3266489917UL;
        h3 = (h3 ^ (h2 >> 5)) * 668265263UL;
        h4 = (h4 + (h3 >> 13)) * 374761393UL;
    }
    snprintf(output, 41, "%08lx%08lx%08lx%08lx%08lx",
             h0 & 0xFFFFFFFF, h1 & 0xFFFFFFFF,
             h2 & 0xFFFFFFFF, h3 & 0xFFFFFFFF,
             h4 & 0xFFFFFFFF);
}

static void des_ecb_xor(const unsigned char *input, unsigned char *output,
                         size_t len, const unsigned char *key, int encrypt) {
    (void)encrypt;
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % 8];
    }
}

static int des_encrypt(const char *plaintext, char *out, size_t out_sz) {
    size_t len = strlen(plaintext);
    size_t pad_len = 8 - (len % 8);
    size_t total = len + pad_len;
    unsigned char *padded = (unsigned char *)calloc(total, 1);
    memcpy(padded, plaintext, len);
    for (size_t i = len; i < total; i++) padded[i] = (unsigned char)pad_len;

    unsigned char *encrypted = (unsigned char *)calloc(total, 1);
    des_ecb_xor(padded, encrypted, total, DES_KEY, 1);

    size_t b64_len = 4 * ((total + 2) / 3);
    if (b64_len >= out_sz) { free(padded); free(encrypted); return -1; }

    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < total; i += 3) {
        unsigned int n = ((unsigned int)encrypted[i]) << 16;
        if (i + 1 < total) n |= ((unsigned int)encrypted[i + 1]) << 8;
        if (i + 2 < total) n |= encrypted[i + 2];
        out[j++] = b64[(n >> 18) & 0x3F];
        out[j++] = b64[(n >> 12) & 0x3F];
        out[j++] = (i + 1 < total) ? b64[(n >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < total) ? b64[n & 0x3F] : '=';
    }
    out[j] = '\0';

    free(padded);
    free(encrypted);
    return 0;
}

static int des_decrypt(const char *ciphertext, char *out, size_t out_sz) {
    size_t in_len = strlen(ciphertext);
    size_t data_len = (in_len / 4) * 3;
    if (ciphertext[in_len - 1] == '=') data_len--;
    if (ciphertext[in_len - 2] == '=') data_len--;

    unsigned char *data = (unsigned char *)calloc(data_len + 4, 1);
    static const int b64_inv[128] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };

    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        unsigned int n = 0;
        for (int k = 0; k < 4; k++) {
            n <<= 6;
            if (ciphertext[i + k] != '=')
                n |= b64_inv[(int)ciphertext[i + k]];
        }
        if (j < data_len) data[j++] = (n >> 16) & 0xFF;
        if (j < data_len) data[j++] = (n >> 8) & 0xFF;
        if (j < data_len) data[j++] = n & 0xFF;
    }

    unsigned char *decrypted = (unsigned char *)calloc(data_len + 1, 1);
    des_ecb_xor(data, decrypted, data_len, DES_KEY, 0);

    size_t pad = decrypted[data_len - 1];
    size_t plain_len = data_len - pad;
    if (plain_len >= out_sz) plain_len = out_sz - 1;
    memcpy(out, decrypted, plain_len);
    out[plain_len] = '\0';

    free(data);
    free(decrypted);
    return 0;
}

static void compute_signature(const char *data, char *out) {
    char combined[8192];
    snprintf(combined, sizeof(combined), "%s%s", data, SIGNING_SECRET);
    md5_simple(combined, out);
}

static void init_data(void) {
    users[0] = (User){1, "admin", "admin@shieldcrypt.io", "", "admin", 1};
    md5_simple("admin2024!", users[0].password_hash);
    users[1] = (User){2, "jnguyen", "jnguyen@shieldcrypt.io", "", "manager", 1};
    md5_simple("jenny_n99", users[1].password_hash);
    users[2] = (User){3, "mwilson", "mwilson@shieldcrypt.io", "", "analyst", 1};
    sha1_simple("mark_w!", users[2].password_hash);
    users[3] = (User){4, "kbrown", "kbrown@shieldcrypt.io", "", "viewer", 0};
    md5_simple("kate_view", users[3].password_hash);

    memset(sessions, 0, sizeof(sessions));
    memset(records, 0, sizeof(records));
    memset(api_tokens, 0, sizeof(api_tokens));
}

static User *find_user_by_username(const char *username) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (strcmp(users[i].username, username) == 0) return &users[i];
    }
    return NULL;
}

static char *create_session(int user_id) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].in_use) {
            snprintf(sessions[i].token, sizeof(sessions[i].token),
                     "%08x%08x%08x%08x",
                     (unsigned)rand(), (unsigned)rand(),
                     (unsigned)rand(), (unsigned)rand());
            sessions[i].user_id = user_id;
            sessions[i].in_use = 1;
            return sessions[i].token;
        }
    }
    return NULL;
}

static Session *find_session(const char *token) {
    if (!token) return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].in_use && strcmp(sessions[i].token, token) == 0)
            return &sessions[i];
    }
    return NULL;
}

static const char *get_bearer_token(struct MHD_Connection *conn) {
    const char *auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
    if (auth && strncmp(auth, "Bearer ", 7) == 0) return auth + 7;
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

static char *generate_api_token_str(void) {
    static char buf[25];
    token_seq++;
    char raw[64];
    snprintf(raw, sizeof(raw), "tkn-%d-%ld", token_seq, (long)time(NULL));
    char hash[41];
    sha1_simple(raw, hash);
    strncpy(buf, hash, 24);
    buf[24] = '\0';
    return buf;
}

static enum MHD_Result handle_login(struct MHD_Connection *conn, const char *body) {
    char username[64] = {0}, password[128] = {0};
    extract_json_string(body, "username", username, sizeof(username));
    extract_json_string(body, "password", password, sizeof(password));

    User *user = find_user_by_username(username);
    if (user) {
        char provided_hash[41] = {0};
        if (user->id == 3) {
            sha1_simple(password, provided_hash);
        } else {
            md5_simple(password, provided_hash);
        }
        if (strcmp(provided_hash, user->password_hash) == 0) {
            char *token = create_session(user->id);
            if (!token) return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                         "{\"error\":\"Session limit\"}");
            char buf[BUF_SIZE];
            snprintf(buf, sizeof(buf),
                     "{\"token\":\"%s\",\"userId\":%d,\"role\":\"%s\"}",
                     token, user->id, user->role);
            return send_json(conn, MHD_HTTP_OK, buf);
        }
    }
    return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Invalid credentials\"}");
}

static enum MHD_Result handle_create_record(struct MHD_Connection *conn, const char *body) {
    const char *bearer = get_bearer_token(conn);
    Session *sess = find_session(bearer);
    if (!sess) return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");

    char content[4096] = {0};
    if (!extract_json_string(body, "content", content, sizeof(content)))
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Content required\"}");

    record_counter++;
    int id = record_counter;

    for (int i = 0; i < MAX_RECORDS; i++) {
        if (!records[i].in_use) {
            records[i].id = id;
            des_encrypt(content, records[i].encrypted_content, sizeof(records[i].encrypted_content));
            compute_signature(content, records[i].signature);
            records[i].owner_id = sess->user_id;
            records[i].in_use = 1;

            char buf[BUF_SIZE];
            snprintf(buf, sizeof(buf),
                     "{\"id\":%d,\"signature\":\"%s\",\"message\":\"Record encrypted and stored\"}",
                     id, records[i].signature);
            return send_json(conn, MHD_HTTP_OK, buf);
        }
    }
    return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Storage full\"}");
}

static enum MHD_Result handle_get_record(struct MHD_Connection *conn, int record_id) {
    const char *bearer = get_bearer_token(conn);
    Session *sess = find_session(bearer);
    if (!sess) return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");

    for (int i = 0; i < MAX_RECORDS; i++) {
        if (records[i].in_use && records[i].id == record_id) {
            char decrypted[4096] = {0};
            des_decrypt(records[i].encrypted_content, decrypted, sizeof(decrypted));
            char buf[BUF_SIZE];
            snprintf(buf, sizeof(buf),
                     "{\"id\":%d,\"content\":\"%s\",\"signature\":\"%s\",\"ownerId\":%d}",
                     records[i].id, decrypted, records[i].signature, records[i].owner_id);
            return send_json(conn, MHD_HTTP_OK, buf);
        }
    }
    return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Record not found\"}");
}

static enum MHD_Result handle_generate_token(struct MHD_Connection *conn, const char *body) {
    const char *bearer = get_bearer_token(conn);
    Session *sess = find_session(bearer);
    if (!sess) return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");

    char label[64] = "default";
    extract_json_string(body, "label", label, sizeof(label));

    char *token = generate_api_token_str();
    for (int i = 0; i < MAX_TOKENS; i++) {
        if (!api_tokens[i].in_use) {
            strncpy(api_tokens[i].token, token, sizeof(api_tokens[i].token) - 1);
            strncpy(api_tokens[i].label, label, sizeof(api_tokens[i].label) - 1);
            api_tokens[i].owner_id = sess->user_id;
            api_tokens[i].in_use = 1;

            char buf[BUF_SIZE];
            snprintf(buf, sizeof(buf), "{\"token\":\"%s\",\"label\":\"%s\"}", token, label);
            return send_json(conn, MHD_HTTP_OK, buf);
        }
    }
    return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Token limit\"}");
}

static enum MHD_Result handle_validate_token(struct MHD_Connection *conn, const char *body) {
    char token[25] = {0};
    extract_json_string(body, "token", token, sizeof(token));

    for (int i = 0; i < MAX_TOKENS; i++) {
        if (api_tokens[i].in_use && strcmp(api_tokens[i].token, token) == 0) {
            char buf[BUF_SIZE];
            snprintf(buf, sizeof(buf),
                     "{\"valid\":true,\"label\":\"%s\",\"ownerId\":%d}",
                     api_tokens[i].label, api_tokens[i].owner_id);
            return send_json(conn, MHD_HTTP_OK, buf);
        }
    }
    return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"valid\":false}");
}

static enum MHD_Result handle_hash(struct MHD_Connection *conn, const char *body) {
    char value[1024] = {0}, algorithm[16] = "md5";
    extract_json_string(body, "value", value, sizeof(value));
    extract_json_string(body, "algorithm", algorithm, sizeof(algorithm));

    char result[41] = {0};
    if (strcmp(algorithm, "sha1") == 0) {
        sha1_simple(value, result);
    } else {
        md5_simple(value, result);
    }

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf), "{\"hash\":\"%s\",\"algorithm\":\"%s\"}", result, algorithm);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_encrypt(struct MHD_Connection *conn, const char *body) {
    char plaintext[4096] = {0};
    extract_json_string(body, "plaintext", plaintext, sizeof(plaintext));

    char encrypted[8192] = {0};
    des_encrypt(plaintext, encrypted, sizeof(encrypted));

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf), "{\"ciphertext\":\"%s\"}", encrypted);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_decrypt(struct MHD_Connection *conn, const char *body) {
    const char *bearer = get_bearer_token(conn);
    Session *sess = find_session(bearer);
    if (!sess) return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");

    char ciphertext[8192] = {0};
    extract_json_string(body, "ciphertext", ciphertext, sizeof(ciphertext));

    char decrypted[4096] = {0};
    des_decrypt(ciphertext, decrypted, sizeof(decrypted));

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf), "{\"plaintext\":\"%s\"}", decrypted);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_list_users(struct MHD_Connection *conn) {
    const char *bearer = get_bearer_token(conn);
    Session *sess = find_session(bearer);
    if (!sess) return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");

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

static int parse_record_id(const char *url) {
    const char *prefix = "/api/records/";
    if (strncmp(url, prefix, strlen(prefix)) != 0) return -1;
    return atoi(url + strlen(prefix));
}

static enum MHD_Result handle_request(void *cls, struct MHD_Connection *conn,
    const char *url, const char *method, const char *version,
    const char *upload_data, size_t *upload_data_size, void **con_cls) {

    (void)cls; (void)version;

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
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/records") == 0) {
        ret = handle_create_record(conn, pd->data);
    } else if (strcmp(method, "GET") == 0 && strncmp(url, "/api/records/", 13) == 0) {
        int id = parse_record_id(url);
        ret = handle_get_record(conn, id);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/tokens/generate") == 0) {
        ret = handle_generate_token(conn, pd->data);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/tokens/validate") == 0) {
        ret = handle_validate_token(conn, pd->data);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/hash") == 0) {
        ret = handle_hash(conn, pd->data);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/encrypt") == 0) {
        ret = handle_encrypt(conn, pd->data);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/decrypt") == 0) {
        ret = handle_decrypt(conn, pd->data);
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
    (void)argc; (void)argv;
    srand((unsigned)time(NULL));
    init_data();

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
        &handle_request, NULL, MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        return 1;
    }

    printf("ShieldCrypt API running on port %d\n", PORT);
    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}
