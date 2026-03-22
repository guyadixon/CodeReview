#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>

#define PORT 8090
#define MAX_USERS 4
#define MAX_RECORDS 4
#define MAX_SESSIONS 4
#define BUF_SIZE 4096

typedef struct {
    int id;
    char username[64];
    char email[128];
    char role[32];
    char ssn[16];
    int salary;
    char department[64];
} User;

typedef struct {
    int id;
    int patient_id;
    char diagnosis[256];
    char medication[256];
    char doctor_notes[512];
    char status[32];
} MedicalRecord;

typedef struct {
    char token[64];
    int user_id;
    char role[32];
} Session;

static User users[MAX_USERS] = {
    {1, "dr_smith", "smith@clinic.io", "admin", "123-45-6789", 250000, "administration"},
    {2, "dr_jones", "jones@clinic.io", "doctor", "987-65-4321", 180000, "cardiology"},
    {3, "patient_a", "patient_a@mail.com", "patient", "555-12-3456", 0, ""},
    {4, "patient_b", "patient_b@mail.com", "patient", "444-33-2211", 0, ""}
};

static MedicalRecord records[MAX_RECORDS] = {
    {501, 3, "Hypertension Stage 2", "Lisinopril 20mg daily",
     "BP consistently elevated. Monitor kidney function.", "active"},
    {502, 3, "Type 2 Diabetes", "Metformin 500mg twice daily",
     "A1C at 7.2. Diet counseling recommended.", "active"},
    {503, 4, "Seasonal Allergies", "Cetirizine 10mg daily",
     "Mild symptoms. OTC antihistamine sufficient.", "active"},
    {504, 4, "Ankle Sprain", "Ibuprofen 400mg as needed",
     "Grade 1 sprain. RICE protocol. Follow up in 2 weeks.", "resolved"}
};

static Session sessions[MAX_SESSIONS] = {
    {"tok_smith", 1, "admin"},
    {"tok_jones", 2, "doctor"},
    {"tok_patient_a", 3, "patient"},
    {"tok_patient_b", 4, "patient"}
};

static Session *find_session(const char *token) {
    if (!token) return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (strcmp(sessions[i].token, token) == 0) {
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


static User *find_user(int id) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].id == id) return &users[i];
    }
    return NULL;
}

static MedicalRecord *find_record(int id) {
    for (int i = 0; i < MAX_RECORDS; i++) {
        if (records[i].id == id) return &records[i];
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

static enum MHD_Result handle_get_user(struct MHD_Connection *conn, int user_id) {
    User *user = find_user(user_id);
    if (!user) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
    }

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf),
        "{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\",\"role\":\"%s\","
        "\"ssn\":\"%s\",\"salary\":%d,\"department\":\"%s\"}",
        user->id, user->username, user->email, user->role,
        user->ssn, user->salary, user->department);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_get_record(struct MHD_Connection *conn, int record_id) {
    const char *token = get_bearer_token(conn);
    Session *sess = find_session(token);
    if (!sess) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    MedicalRecord *rec = find_record(record_id);
    if (!rec) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Record not found\"}");
    }

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf),
        "{\"id\":%d,\"patient_id\":%d,\"diagnosis\":\"%s\","
        "\"medication\":\"%s\",\"doctor_notes\":\"%s\",\"status\":\"%s\"}",
        rec->id, rec->patient_id, rec->diagnosis,
        rec->medication, rec->doctor_notes, rec->status);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_admin_users(struct MHD_Connection *conn) {
    const char *token = get_bearer_token(conn);
    Session *sess = find_session(token);
    if (!sess) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    const char *client_role = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-User-Role");
    if (!client_role || strcmp(client_role, "admin") != 0) {
        return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Admin access required\"}");
    }

    char buf[BUF_SIZE];
    int offset = 0;
    offset += snprintf(buf + offset, sizeof(buf) - offset, "{\"users\":[");
    for (int i = 0; i < MAX_USERS; i++) {
        if (i > 0) offset += snprintf(buf + offset, sizeof(buf) - offset, ",");
        offset += snprintf(buf + offset, sizeof(buf) - offset,
            "{\"id\":%d,\"username\":\"%s\",\"email\":\"%s\",\"role\":\"%s\","
            "\"ssn\":\"%s\",\"salary\":%d}",
            users[i].id, users[i].username, users[i].email, users[i].role,
            users[i].ssn, users[i].salary);
    }
    snprintf(buf + offset, sizeof(buf) - offset, "]}");
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_update_record(struct MHD_Connection *conn, int record_id,
    const char *body) {
    const char *token = get_bearer_token(conn);
    Session *sess = find_session(token);
    if (!sess) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    MedicalRecord *rec = find_record(record_id);
    if (!rec) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Record not found\"}");
    }

    const char *diag = strstr(body, "\"diagnosis\":\"");
    if (diag) {
        diag += 13;
        const char *end = strchr(diag, '"');
        if (end) {
            size_t len = end - diag;
            if (len >= sizeof(rec->diagnosis)) len = sizeof(rec->diagnosis) - 1;
            strncpy(rec->diagnosis, diag, len);
            rec->diagnosis[len] = '\0';
        }
    }

    const char *med = strstr(body, "\"medication\":\"");
    if (med) {
        med += 14;
        const char *end = strchr(med, '"');
        if (end) {
            size_t len = end - med;
            if (len >= sizeof(rec->medication)) len = sizeof(rec->medication) - 1;
            strncpy(rec->medication, med, len);
            rec->medication[len] = '\0';
        }
    }

    const char *st = strstr(body, "\"status\":\"");
    if (st) {
        st += 10;
        const char *end = strchr(st, '"');
        if (end) {
            size_t len = end - st;
            if (len >= sizeof(rec->status)) len = sizeof(rec->status) - 1;
            strncpy(rec->status, st, len);
            rec->status[len] = '\0';
        }
    }

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf),
        "{\"message\":\"Record updated\",\"record\":{\"id\":%d,\"patient_id\":%d,"
        "\"diagnosis\":\"%s\",\"medication\":\"%s\",\"status\":\"%s\"}}",
        rec->id, rec->patient_id, rec->diagnosis, rec->medication, rec->status);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_update_role(struct MHD_Connection *conn, int user_id,
    const char *body) {
    const char *token = get_bearer_token(conn);
    Session *sess = find_session(token);
    if (!sess) {
        return send_json(conn, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Authentication required\"}");
    }

    User *user = find_user(user_id);
    if (!user) {
        return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");
    }

    const char *role_ptr = strstr(body, "\"role\":\"");
    char new_role[32] = "patient";
    if (role_ptr) {
        role_ptr += 8;
        const char *end = strchr(role_ptr, '"');
        if (end) {
            size_t len = end - role_ptr;
            if (len >= sizeof(new_role)) len = sizeof(new_role) - 1;
            strncpy(new_role, role_ptr, len);
            new_role[len] = '\0';
        }
    }
    strncpy(user->role, new_role, sizeof(user->role) - 1);
    user->role[sizeof(user->role) - 1] = '\0';

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf),
        "{\"message\":\"Role updated\",\"userId\":%d,\"newRole\":\"%s\"}",
        user_id, new_role);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static enum MHD_Result handle_debug_config(struct MHD_Connection *conn) {
    const char *db_url = getenv("DATABASE_URL");
    if (!db_url) db_url = "postgres://admin:s3cret@db:5432/clinicdb";
    const char *secret = getenv("APP_SECRET");
    if (!secret) secret = "clinic-api-secret-key-prod";

    char buf[BUF_SIZE];
    snprintf(buf, sizeof(buf),
        "{\"databaseUrl\":\"%s\",\"appSecret\":\"%s\","
        "\"apiKeys\":{\"twilio\":\"%s\",\"sendgrid\":\"%s\"}}",
        db_url, secret,
        getenv("TWILIO_KEY") ? getenv("TWILIO_KEY") : "AC_twilio_123",
        getenv("SENDGRID_KEY") ? getenv("SENDGRID_KEY") : "SG.sendgrid_456");
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
    int id;

    if (strcmp(method, "GET") == 0 && sscanf(url, "/api/users/%d", &id) == 1
        && strstr(url, "/role") == NULL) {
        ret = handle_get_user(conn, id);
    } else if (strcmp(method, "GET") == 0 && sscanf(url, "/api/records/%d", &id) == 1) {
        ret = handle_get_record(conn, id);
    } else if (strcmp(method, "PUT") == 0 && sscanf(url, "/api/records/%d", &id) == 1) {
        ret = handle_update_record(conn, id, pd->data);
    } else if (strcmp(method, "PUT") == 0 && sscanf(url, "/api/users/%d/role", &id) == 1) {
        ret = handle_update_role(conn, id, pd->data);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/admin/users") == 0) {
        ret = handle_admin_users(conn);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/api/debug/config") == 0) {
        ret = handle_debug_config(conn);
    } else {
        ret = send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Not found\"}");
    }

    free(pd);
    *con_cls = NULL;
    return ret;
}

int main(int argc, char *argv[]) {
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
        &handle_request, NULL, MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        return 1;
    }

    printf("Clinic Records API running on port %d\n", PORT);
    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}
