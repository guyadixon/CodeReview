#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <curl/curl.h>
#include <jansson.h>

#define PORT 9010
#define MAX_PRODUCTS 32
#define MAX_ORDERS 64
#define MAX_POST_SIZE 8192

struct product {
    int id;
    char name[128];
    double price;
    int stock;
    char category[64];
};

struct order_item {
    int product_id;
    char name[128];
    int quantity;
    double subtotal;
};

struct order {
    int id;
    struct order_item items[16];
    int item_count;
    double total;
    char status[32];
    char customer_email[128];
};

static struct product products[MAX_PRODUCTS];
static int product_count = 0;
static struct order orders[MAX_ORDERS];
static int order_count = 0;
static int order_counter = 1000;

static const char *WAREHOUSE_ENDPOINT = "https://warehouse.internal.acmecorp.io/api/v2";

static void init_data(void) {
    struct product defaults[] = {
        {1, "Widget Pro", 29.99, 150, "hardware"},
        {2, "Gadget Plus", 49.99, 75, "electronics"},
        {3, "Tool Kit Standard", 19.99, 200, "tools"},
        {4, "Sensor Array", 89.99, 30, "electronics"},
        {5, "Cable Bundle", 9.99, 500, "accessories"},
    };
    product_count = 5;
    memcpy(products, defaults, sizeof(defaults));
}

static struct product *find_product(int id) {
    for (int i = 0; i < product_count; i++) {
        if (products[i].id == id) return &products[i];
    }
    return NULL;
}

static const char *extract_json_string(const char *json_str, const char *key, char *buf, size_t buf_sz) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json_str, pattern);
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

static enum MHD_Result handle_list_products(struct MHD_Connection *conn) {
    const char *category = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "category");

    json_t *arr = json_array();
    int count = 0;
    for (int i = 0; i < product_count; i++) {
        if (category && strlen(category) > 0 && strcmp(products[i].category, category) != 0)
            continue;
        json_t *obj = json_object();
        json_object_set_new(obj, "id", json_integer(products[i].id));
        json_object_set_new(obj, "name", json_string(products[i].name));
        json_object_set_new(obj, "price", json_real(products[i].price));
        json_object_set_new(obj, "stock", json_integer(products[i].stock));
        json_object_set_new(obj, "category", json_string(products[i].category));
        json_array_append_new(arr, obj);
        count++;
    }

    json_t *result = json_object();
    json_object_set_new(result, "products", arr);
    json_object_set_new(result, "total", json_integer(count));
    char *out = json_dumps(result, JSON_COMPACT);
    enum MHD_Result ret = send_json(conn, MHD_HTTP_OK, out);
    free(out);
    json_decref(result);
    return ret;
}

static enum MHD_Result handle_get_product(struct MHD_Connection *conn, int product_id) {
    struct product *p = find_product(product_id);
    if (!p) return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Product not found\"}");

    json_t *obj = json_object();
    json_object_set_new(obj, "id", json_integer(p->id));
    json_object_set_new(obj, "name", json_string(p->name));
    json_object_set_new(obj, "price", json_real(p->price));
    json_object_set_new(obj, "stock", json_integer(p->stock));
    json_object_set_new(obj, "category", json_string(p->category));
    char *out = json_dumps(obj, JSON_COMPACT);
    enum MHD_Result ret = send_json(conn, MHD_HTTP_OK, out);
    free(out);
    json_decref(obj);
    return ret;
}

static enum MHD_Result handle_create_order(struct MHD_Connection *conn, const char *body) {
    json_error_t err;
    json_t *root = json_loads(body, 0, &err);
    if (!root) return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid JSON\"}");

    json_t *items = json_object_get(root, "items");
    if (!json_is_array(items) || json_array_size(items) == 0) {
        json_decref(root);
        return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"At least one item required\"}");
    }

    if (order_count >= MAX_ORDERS) {
        json_decref(root);
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Order limit reached\"}");
    }

    struct order *o = &orders[order_count];
    o->item_count = 0;
    o->total = 0.0;

    for (size_t i = 0; i < json_array_size(items); i++) {
        json_t *item = json_array_get(items, i);
        int pid = json_integer_value(json_object_get(item, "product_id"));
        int qty = json_integer_value(json_object_get(item, "quantity"));
        if (qty <= 0) qty = 1;

        struct product *p = find_product(pid);
        if (!p) {
            json_decref(root);
            char resp[128];
            snprintf(resp, sizeof(resp), "{\"error\":\"Product %d not found\"}", pid);
            return send_json(conn, MHD_HTTP_NOT_FOUND, resp);
        }
        if (p->stock < qty) {
            json_decref(root);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"error\":\"Insufficient stock for %s\"}", p->name);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, resp);
        }

        p->stock -= qty;
        double subtotal = p->price * qty;
        o->total += subtotal;
        struct order_item *oi = &o->items[o->item_count++];
        oi->product_id = pid;
        strncpy(oi->name, p->name, sizeof(oi->name) - 1);
        oi->quantity = qty;
        oi->subtotal = subtotal;
    }

    order_counter++;
    o->id = order_counter;
    strncpy(o->status, "confirmed", sizeof(o->status) - 1);

    json_t *email_val = json_object_get(root, "email");
    if (json_is_string(email_val)) {
        strncpy(o->customer_email, json_string_value(email_val), sizeof(o->customer_email) - 1);
    }

    order_count++;
    json_decref(root);

    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"order_id\":%d,\"total\":%.2f,\"status\":\"confirmed\"}", o->id, o->total);
    return send_json(conn, MHD_HTTP_CREATED, resp);
}

static enum MHD_Result handle_get_order(struct MHD_Connection *conn, int order_id) {
    for (int i = 0; i < order_count; i++) {
        if (orders[i].id == order_id) {
            json_t *obj = json_object();
            json_object_set_new(obj, "id", json_integer(orders[i].id));
            json_object_set_new(obj, "total", json_real(orders[i].total));
            json_object_set_new(obj, "status", json_string(orders[i].status));
            json_object_set_new(obj, "customer_email", json_string(orders[i].customer_email));

            json_t *arr = json_array();
            for (int j = 0; j < orders[i].item_count; j++) {
                json_t *it = json_object();
                json_object_set_new(it, "product_id", json_integer(orders[i].items[j].product_id));
                json_object_set_new(it, "name", json_string(orders[i].items[j].name));
                json_object_set_new(it, "quantity", json_integer(orders[i].items[j].quantity));
                json_object_set_new(it, "subtotal", json_real(orders[i].items[j].subtotal));
                json_array_append_new(arr, it);
            }
            json_object_set_new(obj, "items", arr);

            char *out = json_dumps(obj, JSON_COMPACT);
            enum MHD_Result ret = send_json(conn, MHD_HTTP_OK, out);
            free(out);
            json_decref(obj);
            return ret;
        }
    }
    return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Order not found\"}");
}

static enum MHD_Result handle_warehouse_config(struct MHD_Connection *conn) {
    char resp[512];
    snprintf(resp, sizeof(resp),
             "{\"location\":\"us-east-1\",\"api_endpoint\":\"%s\","
             "\"max_batch_size\":50,\"retry_attempts\":3}",
             WAREHOUSE_ENDPOINT);
    return send_json(conn, MHD_HTTP_OK, resp);
}

static enum MHD_Result handle_health(struct MHD_Connection *conn) {
    return send_json(conn, MHD_HTTP_OK, "{\"status\":\"healthy\",\"service\":\"inventory-api\"}");
}

struct post_data {
    char buffer[MAX_POST_SIZE];
    size_t size;
};

static int parse_id_from_url(const char *url, const char *prefix) {
    const char *p = url + strlen(prefix);
    return atoi(p);
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

    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/products") == 0) {
        ret = handle_list_products(conn);
    } else if (strcmp(method, "GET") == 0 && strncmp(url, "/api/products/", 14) == 0
               && strchr(url + 14, '/') == NULL) {
        int pid = parse_id_from_url(url, "/api/products/");
        ret = handle_get_product(conn, pid);
    } else if (strcmp(method, "POST") == 0 && strcmp(url, "/api/orders") == 0) {
        ret = handle_create_order(conn, pd->buffer);
    } else if (strcmp(method, "GET") == 0 && strncmp(url, "/api/orders/", 12) == 0) {
        int oid = parse_id_from_url(url, "/api/orders/");
        ret = handle_get_order(conn, oid);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/config/warehouse") == 0) {
        ret = handle_warehouse_config(conn);
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
    curl_global_init(CURL_GLOBAL_DEFAULT);

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        return 1;
    }

    printf("Inventory Service API running on port %d\n", PORT);
    getchar();
    MHD_stop_daemon(daemon);
    curl_global_cleanup();
    return 0;
}
