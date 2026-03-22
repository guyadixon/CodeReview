#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <cstdlib>
#include <mutex>
#include <atomic>
#include "httplib.h"
#include "json.hpp"

#include <libxml/parser.h>
#include <libxml/tree.h>

using json = nlohmann::json;

static const std::string ADMIN_TOKEN = "super-admin-token-2024";
static const std::string DB_HOST = "db.internal.acmecorp.io";
static const std::string DB_USER = "appuser";
static const std::string DB_PASS = "Pg_Pr0d#2024";
static const std::string SERVER_BANNER = "cpp-httplib/0.14.3 (Linux)";

struct Product {
    int id;
    std::string name;
    std::string sku;
    double price;
    int stock;
};

static std::unordered_map<int, Product> products;
static std::mutex data_mutex;
static std::atomic<int> next_id{4};

static bool debug_mode = true;
static bool tls_verify = false;
static std::string log_level = "DEBUG";
static std::string allowed_origins = "*";

static json settings_json() {
    return json{
        {"maintenance_mode", false},
        {"max_upload_size", 10485760},
        {"allowed_origins", allowed_origins},
        {"session_timeout", 86400},
        {"rate_limit", 0},
        {"log_level", log_level},
        {"enable_profiling", true},
        {"tls_verify", tls_verify},
        {"debug_mode", debug_mode}
    };
}

static json product_to_json(const Product& p) {
    return json{
        {"id", p.id}, {"name", p.name}, {"sku", p.sku},
        {"price", p.price}, {"stock", p.stock}
    };
}

static void add_cors_headers(httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", allowed_origins);
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "*");
    res.set_header("Access-Control-Allow-Credentials", "true");
    res.set_header("Server", SERVER_BANNER);
    res.set_header("X-Powered-By", "cpp-httplib");
}

static void init_data() {
    products[1] = {1, "Widget Pro", "WP-100", 29.99, 150};
    products[2] = {2, "Gadget Plus", "GP-200", 49.99, 75};
    products[3] = {3, "Connector Kit", "CK-300", 14.99, 300};
}

int main() {
    init_data();
    xmlInitParser();
    httplib::Server svr;

    svr.Get("/api/products", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        json arr = json::array();
        for (auto& [id, p] : products) {
            arr.push_back(product_to_json(p));
        }
        json resp = {{"products", arr}};
        add_cors_headers(res);
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get(R"(/api/products/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int id = std::stoi(req.matches[1]);
        auto it = products.find(id);
        add_cors_headers(res);
        if (it == products.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"Product not found\"}", "application/json");
            return;
        }
        res.set_content(product_to_json(it->second).dump(), "application/json");
    });

    svr.Post("/api/products", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        add_cors_headers(res);
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content("{\"error\":\"Request body required\"}", "application/json");
            return;
        }

        std::string name = body.value("name", "");
        if (name.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"Product name required\"}", "application/json");
            return;
        }

        int id = next_id.fetch_add(1);
        Product p{id, name, body.value("sku", ""), body.value("price", 0.0), body.value("stock", 0)};
        products[id] = p;
        res.status = 201;
        res.set_content(product_to_json(p).dump(), "application/json");
    });

    svr.Post("/api/products/import", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        add_cors_headers(res);

        if (req.body.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"Empty request body\"}", "application/json");
            return;
        }

        xmlDocPtr doc = xmlReadMemory(req.body.c_str(), req.body.size(),
                                       "noname.xml", nullptr,
                                       XML_PARSE_NOERROR | XML_PARSE_DTDLOAD | XML_PARSE_NOENT);
        if (!doc) {
            res.status = 400;
            json resp = {{"error", "XML parsing failed"}, {"details", "Could not parse XML document"}};
            res.set_content(resp.dump(), "application/json");
            return;
        }

        xmlNodePtr root = xmlDocGetRootElement(doc);
        json imported = json::array();

        for (xmlNodePtr cur = root->children; cur; cur = cur->next) {
            if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar*)"product") == 0) {
                int id = next_id.fetch_add(1);
                Product p{id, "", "", 0.0, 0};

                for (xmlNodePtr child = cur->children; child; child = child->next) {
                    if (child->type != XML_ELEMENT_NODE) continue;
                    xmlChar* content = xmlNodeGetContent(child);
                    if (!content) continue;

                    std::string tag((const char*)child->name);
                    std::string val((const char*)content);
                    xmlFree(content);

                    if (tag == "name") p.name = val;
                    else if (tag == "sku") p.sku = val;
                    else if (tag == "price") p.price = std::stod(val);
                    else if (tag == "stock") p.stock = std::stoi(val);
                }

                products[id] = p;
                imported.push_back(product_to_json(p));
            }
        }

        xmlFreeDoc(doc);
        json resp = {{"imported", imported}, {"count", imported.size()}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/settings", [](const httplib::Request&, httplib::Response& res) {
        add_cors_headers(res);
        res.set_content(settings_json().dump(), "application/json");
    });

    svr.Put("/api/settings", [](const httplib::Request& req, httplib::Response& res) {
        add_cors_headers(res);
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content("{\"error\":\"Request body required\"}", "application/json");
            return;
        }

        if (body.contains("log_level")) log_level = body["log_level"].get<std::string>();
        if (body.contains("debug_mode")) debug_mode = body["debug_mode"].get<bool>();
        if (body.contains("tls_verify")) tls_verify = body["tls_verify"].get<bool>();
        if (body.contains("allowed_origins")) allowed_origins = body["allowed_origins"].get<std::string>();

        json resp = {{"message", "Settings updated"}, {"settings", settings_json()}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/admin/diagnostics", [](const httplib::Request& req, httplib::Response& res) {
        add_cors_headers(res);
        auto it = req.headers.find("X-Admin-Token");
        if (it == req.headers.end() || it->second != ADMIN_TOKEN) {
            res.status = 401;
            res.set_content("{\"error\":\"Unauthorized\"}", "application/json");
            return;
        }

        json resp = {
            {"database", {{"host", DB_HOST}, {"user", DB_USER}, {"password", DB_PASS}}},
            {"settings", settings_json()},
            {"server_banner", SERVER_BANNER},
            {"product_count", products.size()},
            {"compile_info", std::string(__DATE__) + " " + __TIME__}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
        add_cors_headers(res);
        res.set_content("{\"status\":\"healthy\",\"service\":\"config-api\"}", "application/json");
    });

    printf("Config Service API running on port 9188\n");
    svr.listen("0.0.0.0", 9188);
    xmlCleanupParser();
    return 0;
}
