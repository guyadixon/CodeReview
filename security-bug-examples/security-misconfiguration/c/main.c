#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#define MAX_PRODUCTS 64
#define MAX_POST_SIZE 65536
#define PORT 9088

static const char *ADMIN_TOKEN = "super-admin-token-2024";
static const char *DB_HOST = "db.internal.acmecorp.io";
static const char *DB_USER = "appuser";
static const char *DB_PASS = "Pg_Pr0d#2024";
static const char *SERVER_BANNER = "libmicrohttpd/0.9.77 (Linux)";

struct product {
    int id;
    char name[128];
    char sku[32];
    double price;
    int stock;
};

static struct product products[MAX_PRODUCTS];
static int product_count = 0;
static int next_id = 4;

static int debug_mode = 1;
static int tls_verify = 0;
static const char *log_level = "DEBUG";
static const char *allowed_origins = "*";

static void init_data(void) {
    struct product defaults[] = {
        {1, "Widget Pro", "WP-100", 29.99, 150},
        {2, "Gadget Plus", "GP-200", 49.99, 75},
        {3, "Connector Kit", "CK-300", 14.99, 300},
    };
    product_count = 3;
    memcpy(products, defaults, sizeof(defaults));
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
    if (!p) return 0;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return atof(p);
}

static enum MHD_Result send_json(struct MHD_Connection *conn, int status, const char *json_str) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_add_response_header(resp, "Server", SERVER_BANNER);
    MHD_add_response_header(resp, "X-Powered-By", "libmicrohttpd");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", allowed_origins);
    MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    MHD_add_response_header(resp, "Access-Control-Allow-Headers", "*");
    MHD_add_response_header(resp, "Access-Control-Allow-Credentials", "true");
    enum MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result handle_list_products(struct MHD_Connection *conn) {
    char resp[8192];
    int offset = snprintf(resp, sizeof(resp), "{\"products\":[");
    for (int i = 0; i < product_count; i++) {
        if (i > 0) offset += snprintf(resp + offset, sizeof(resp) - offset, ",");
        offset += snprintf(resp + offset, sizeof(resp) - offset,
            "{\"id\":%d,\"name\":\"%s\",\"sku\":\"%s\",\"price\":%.2f,\"stock\":%d}",
            products[i].id, products[i].name, products[i].sku,
            products[i].price, products[i].stock);
    }
    snprintf(resp + offset, sizeof(resp) - offset, "]}");
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_create_product(struct MHD_Connection *conn, const char *body) {
    char name[128] = {0}, sku[32] = {0};
    extract_json_string(body, "name", name, sizeof(name));
    extract_json_string(body, "sku", sku, sizeof(sku));
    double price = extract_json_number(body, "price");
    int stock = (int)extract_json_number(body, "stock");

    if (strlen(name) == 0) {
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Product name required\"}");
    }

    if (product_count >= MAX_PRODUCTS) {
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Product limit reached\"}");
    }

    struct product *p = &products[product_count++];
    p->id = next_id++;
    strncpy(p->name, name, sizeof(p->name) - 1);
    strncpy(p->sku, sku, sizeof(p->sku) - 1);
    p->price = price;
    p->stock = stock;

    char resp[512];
    snprintf(resp, sizeof(resp),
        "{\"id\":%d,\"name\":\"%s\",\"sku\":\"%s\",\"price\":%.2f,\"stock\":%d}",
        p->id, p->name, p->sku, p->price, p->stock);
    return send_json(conn, MHD_HTTP_CREATED, resp);
}

static enum MHD_Result handle_import_products(struct MHD_Connection *conn, const char *body) {
    if (!body || strlen(body) == 0) {
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Empty request body\"}");
    }

    xmlDocPtr doc = xmlReadMemory(body, strlen(body), "noname.xml", NULL,
                                   XML_PARSE_NOERROR | XML_PARSE_DTDLOAD | XML_PARSE_NOENT);
    if (doc == NULL) {
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"error\":\"XML parsing failed\",\"details\":\"Could not parse XML document\"}");
        return send_json(conn, MHD_HTTP_BAD_REQUEST, resp);
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    int count = 0;
    char resp[8192];
    int offset = snprintf(resp, sizeof(resp), "{\"imported\":[");

    for (xmlNodePtr cur = root->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar *)"product") == 0) {
            if (product_count >= MAX_PRODUCTS) break;

            struct product *p = &products[product_count++];
            p->id = next_id++;
            p->name[0] = '\0';
            p->sku[0] = '\0';
            p->price = 0;
            p->stock = 0;

            for (xmlNodePtr child = cur->children; child; child = child->next) {
                if (child->type != XML_ELEMENT_NODE) continue;
                xmlChar *content = xmlNodeGetContent(child);
                if (content) {
                    if (xmlStrcmp(child->name, (const xmlChar *)"name") == 0)
                        strncpy(p->name, (char *)content, sizeof(p->name) - 1);
                    else if (xmlStrcmp(child->name, (const xmlChar *)"sku") == 0)
                        strncpy(p->sku, (char *)content, sizeof(p->sku) - 1);
                    else if (xmlStrcmp(child->name, (const xmlChar *)"price") == 0)
                        p->price = atof((char *)content);
                    else if (xmlStrcmp(child->name, (const xmlChar *)"stock") == 0)
                        p->stock = atoi((char *)content);
                    xmlFree(content);
                }
            }

            if (count > 0) offset += snprintf(resp + offset, sizeof(resp) - offset, ",");
            offset += snprintf(resp + offset, sizeof(resp) - offset,
                "{\"id\":%d,\"name\":\"%s\",\"sku\":\"%s\",\"price\":%.2f,\"stock\":%d}",
                p->id, p->name, p->sku, p->price, p->stock);
            count++;
        }
    }

    xmlFreeDoc(doc);
    snprintf(resp + offset, sizeof(resp) - offset, "],\"count\":%d}", count);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_get_settings(struct MHD_Connection *conn) {
    char resp[1024];
    snprintf(resp, sizeof(resp),
        "{\"maintenance_mode\":false,\"max_upload_size\":10485760,"
        "\"allowed_origins\":\"%s\",\"session_timeout\":86400,"
        "\"rate_limit\":0,\"log_level\":\"%s\","
        "\"enable_profiling\":true,\"tls_verify\":%s,\"debug_mode\":%s}",
        allowed_origins, log_level,
        tls_verify ? "true" : "false",
        debug_mode ? "true" : "false");
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_diagnostics(struct MHD_Connection *conn) {
    const char *token = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Admin-Token");
    if (!token || strcmp(token, ADMIN_TOKEN) != 0) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Unauthorized\"}");
    }

    char resp[2048];
    snprintf(resp, sizeof(resp),
        "{\"database\":{\"host\":\"%s\",\"user\":\"%s\",\"password\":\"%s\"},"
        "\"debug_mode\":%s,\"log_level\":\"%s\","
        "\"product_count\":%d,\"server_banner\":\"%s\","
        "\"compile_flags\":\"" __DATE__ " " __TIME__ "\"}",
        DB_HOST, DB_USER, DB_PASS,
        debug_mode ? "true" : "false", log_level,
        product_count, SERVER_BANNER);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_health(struct MHD_Connection *conn) {
    return send_json(conn, MHD_HTTP_OK, "{\"status\":\"healthy\",\"service\":\"config-api\"}");
}

struct post_data {
    char buffer[MAX_POST_SIZE];
    size_t size;
};

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

    if (strcmp(method, "OPTIONS") == 0) {
        ret = send_json(conn, MHD_HTTP_NO_CONTENT, "");
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/products") == 0) {
        ret = handle_list_products(conn);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/products") == 0) {
        ret = handle_create_product(conn, pd->buffer);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/products/import") == 0) {
        ret = handle_import_products(conn, pd->buffer);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/settings") == 0) {
        ret = handle_get_settings(conn);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/admin/diagnostics") == 0) {
        ret = handle_diagnostics(conn);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/health") == 0) {
        ret = handle_health(conn);
    } else {
        ret = send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Not found\"}");
    }

    free(pd);
    *con_cls = NULL;
    return ret;
}

int main(int argc, char *argv[]) {
    init_data();
    xmlInitParser();

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        return 1;
    }

    printf("Config Service API running on port %d\n", PORT);
    getchar();
    MHD_stop_daemon(daemon);
    xmlCleanupParser();
    return 0;
}
