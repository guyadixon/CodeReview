#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <ctime>
#include <functional>
#include <mutex>
#include <regex>
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;

struct User {
    int id;
    std::string username;
    std::string email;
    std::string password;
    std::string role;
    bool active;
    std::string api_key;
};

struct SessionData {
    int user_id;
    time_t created;
};

struct WebhookEntry {
    std::string id;
    std::string callback_url;
    std::string event_type;
    int user_id;
    time_t created;
};

static std::unordered_map<int, User> users;
static std::unordered_map<std::string, SessionData> sessions;
static std::unordered_map<std::string, WebhookEntry> webhook_registry;
static std::mutex data_mutex;

static std::string simple_hash(const std::string& input) {
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    std::ostringstream oss;
    oss << std::hex << h;
    return oss.str();
}

static std::string create_session(int user_id) {
    std::string raw = std::to_string(user_id) + "-" + std::to_string(time(nullptr));
    std::string token = simple_hash(raw);
    std::lock_guard<std::mutex> lock(data_mutex);
    sessions[token] = {user_id, time(nullptr)};
    return token;
}

static int get_session_user(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return -1;
    std::string auth = it->second;
    if (auth.substr(0, 7) != "Bearer ") return -1;
    std::string token = auth.substr(7);
    std::lock_guard<std::mutex> lock(data_mutex);
    auto sit = sessions.find(token);
    if (sit == sessions.end()) return -1;
    return sit->second.user_id;
}

static void init_data() {
    users[1] = {1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", true, "ak-admin-x7k9m2"};
    users[2] = {2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", true, "ak-jdoe-p3q8r1"};
    users[3] = {3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", true, "ak-asmith-w5t6y4"};
}

struct UrlParts {
    std::string scheme;
    std::string host;
    int port;
    std::string path;
};

static bool parse_url(const std::string& url, UrlParts& parts) {
    std::regex url_re("^(https?)://([^/:]+)(?::(\\d+))?(/.*)$");
    std::smatch match;
    if (!std::regex_match(url, match, url_re)) {
        std::regex simple_re("^(https?)://([^/:]+)(?::(\\d+))?/?$");
        if (!std::regex_match(url, match, simple_re)) return false;
        parts.scheme = match[1];
        parts.host = match[2];
        parts.port = match[3].length() > 0 ? std::stoi(match[3]) : (parts.scheme == "https" ? 443 : 80);
        parts.path = "/";
        return true;
    }
    parts.scheme = match[1];
    parts.host = match[2];
    parts.port = match[3].length() > 0 ? std::stoi(match[3]) : (parts.scheme == "https" ? 443 : 80);
    parts.path = match[4];
    return true;
}

static std::pair<int, std::string> do_http_get(const std::string& url) {
    UrlParts parts;
    if (!parse_url(url, parts)) return {-1, ""};

    std::string base = parts.scheme + "://" + parts.host + ":" + std::to_string(parts.port);

    if (parts.scheme == "https") {
        httplib::SSLClient cli(parts.host, parts.port);
        cli.set_connection_timeout(10, 0);
        auto res = cli.Get(parts.path);
        if (res) return {res->status, res->body};
        return {-1, ""};
    } else {
        httplib::Client cli(parts.host, parts.port);
        cli.set_connection_timeout(10, 0);
        auto res = cli.Get(parts.path);
        if (res) return {res->status, res->body};
        return {-1, ""};
    }
}

static std::pair<int, std::string> do_http_post(const std::string& url, const std::string& body, const std::string& content_type) {
    UrlParts parts;
    if (!parse_url(url, parts)) return {-1, ""};

    if (parts.scheme == "https") {
        httplib::SSLClient cli(parts.host, parts.port);
        cli.set_connection_timeout(10, 0);
        auto res = cli.Post(parts.path, body, content_type);
        if (res) return {res->status, res->body};
        return {-1, ""};
    } else {
        httplib::Client cli(parts.host, parts.port);
        cli.set_connection_timeout(10, 0);
        auto res = cli.Post(parts.path, body, content_type);
        if (res) return {res->status, res->body};
        return {-1, ""};
    }
}

int main() {
    init_data();
    httplib::Server svr;

    svr.Post("/api/login", [](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.set_content(R"({"error":"Invalid request"})", "application/json");
            res.status = 400;
            return;
        }

        std::string username = body.value("username", "");
        std::string password = body.value("password", "");

        for (auto& [id, user] : users) {
            if (user.username == username && user.password == password) {
                if (!user.active) {
                    res.set_content(R"({"error":"Account disabled"})", "application/json");
                    res.status = 403;
                    return;
                }
                std::string token = create_session(id);
                json resp = {{"token", token}, {"user_id", id}, {"role", user.role}};
                res.set_content(resp.dump(), "application/json");
                return;
            }
        }
        res.set_content(R"({"error":"Invalid credentials"})", "application/json");
        res.status = 401;
    });

    svr.Post("/api/fetch-url", [](const httplib::Request& req, httplib::Response& res) {
        int uid = get_session_user(req);
        if (uid < 0) {
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            res.status = 401;
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string url = body.is_object() ? body.value("url", "") : "";
        if (url.empty()) {
            res.set_content(R"({"error":"URL parameter required"})", "application/json");
            res.status = 400;
            return;
        }

        auto [status, content] = do_http_get(url);
        if (status < 0) {
            res.set_content(R"({"error":"Failed to fetch URL"})", "application/json");
            res.status = 502;
            return;
        }

        json resp = {
            {"status", status},
            {"content_length", content.size()},
            {"body", content.substr(0, 5000)}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/preview", [](const httplib::Request& req, httplib::Response& res) {
        int uid = get_session_user(req);
        if (uid < 0) {
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            res.status = 401;
            return;
        }

        std::string target = req.get_param_value("target");
        if (target.empty()) {
            res.set_content(R"({"error":"target parameter required"})", "application/json");
            res.status = 400;
            return;
        }

        UrlParts parts;
        if (parse_url(target, parts)) {
            if (parts.host == "localhost" || parts.host == "127.0.0.1") {
                res.set_content(R"({"error":"Blocked host"})", "application/json");
                res.status = 403;
                return;
            }
        }

        auto [status, content] = do_http_get(target);
        if (status < 0) {
            res.set_content(R"({"error":"Failed to fetch URL"})", "application/json");
            res.status = 502;
            return;
        }

        json resp = {{"url", target}, {"preview", content.substr(0, 2000)}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/webhooks", [](const httplib::Request& req, httplib::Response& res) {
        int uid = get_session_user(req);
        if (uid < 0) {
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            res.status = 401;
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string callback_url = body.is_object() ? body.value("callback_url", "") : "";
        std::string event_type = body.is_object() ? body.value("event_type", "default") : "default";

        if (callback_url.empty()) {
            res.set_content(R"({"error":"callback_url required"})", "application/json");
            res.status = 400;
            return;
        }

        if (callback_url.substr(0, 7) != "http://" && callback_url.substr(0, 8) != "https://") {
            res.set_content(R"({"error":"Only HTTP(S) callbacks supported"})", "application/json");
            res.status = 400;
            return;
        }

        std::string webhook_id = simple_hash(callback_url + std::to_string(time(nullptr))).substr(0, 12);
        {
            std::lock_guard<std::mutex> lock(data_mutex);
            webhook_registry[webhook_id] = {webhook_id, callback_url, event_type, uid, time(nullptr)};
        }

        json resp = {{"message", "Webhook registered"}, {"webhook_id", webhook_id}};
        res.set_content(resp.dump(), "application/json");
        res.status = 201;
    });

    svr.Post(R"(/api/webhooks/(\w+)/test)", [](const httplib::Request& req, httplib::Response& res) {
        int uid = get_session_user(req);
        if (uid < 0) {
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            res.status = 401;
            return;
        }

        std::string webhook_id = req.matches[1];
        std::string callback_url;
        {
            std::lock_guard<std::mutex> lock(data_mutex);
            auto it = webhook_registry.find(webhook_id);
            if (it == webhook_registry.end()) {
                res.set_content(R"({"error":"Webhook not found"})", "application/json");
                res.status = 404;
                return;
            }
            callback_url = it->second.callback_url;
        }

        json payload = {{"event", "test"}, {"timestamp", time(nullptr)}};
        auto [status, body] = do_http_post(callback_url, payload.dump(), "application/json");

        if (status >= 0) {
            json resp = {{"message", "Webhook delivered"}, {"status", status}};
            res.set_content(resp.dump(), "application/json");
        } else {
            res.set_content(R"({"error":"Delivery failed"})", "application/json");
            res.status = 502;
        }
    });

    svr.Post("/api/integrations/import", [](const httplib::Request& req, httplib::Response& res) {
        int uid = get_session_user(req);
        if (uid < 0) {
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            res.status = 401;
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string config_url = body.is_object() ? body.value("config_url", "") : "";
        if (config_url.empty()) {
            res.set_content(R"({"error":"config_url required"})", "application/json");
            res.status = 400;
            return;
        }

        if (config_url.substr(0, 7) != "http://" && config_url.substr(0, 8) != "https://") {
            res.set_content(R"({"error":"Only HTTP(S) URLs supported"})", "application/json");
            res.status = 400;
            return;
        }

        UrlParts parts;
        if (parse_url(config_url, parts) && parts.host.find("169.254") == 0) {
            res.set_content(R"({"error":"Metadata endpoints not allowed"})", "application/json");
            res.status = 403;
            return;
        }

        auto [status, content] = do_http_get(config_url);
        if (status < 0) {
            res.set_content(R"({"error":"Failed to fetch config"})", "application/json");
            res.status = 502;
            return;
        }

        auto config = json::parse(content, nullptr, false);
        if (config.is_discarded()) {
            res.set_content(R"({"error":"Invalid JSON at URL"})", "application/json");
            res.status = 400;
            return;
        }

        json resp = {{"message", "Configuration imported"}, {"config", config}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/proxy", [](const httplib::Request& req, httplib::Response& res) {
        int uid = get_session_user(req);
        if (uid < 0) {
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            res.status = 401;
            return;
        }

        std::string service = req.get_param_value("service");
        std::string path = req.get_param_value("path");
        std::string base_url = req.get_param_value("base_url");
        if (path.empty()) path = "/";

        std::unordered_map<std::string, std::string> service_map = {
            {"analytics", "http://analytics-service:8081"},
            {"billing", "http://billing-service:8082"},
            {"notifications", "http://notifications-service:8083"},
        };

        std::string resolved_base;
        auto it = service_map.find(service);
        if (it != service_map.end()) {
            resolved_base = it->second;
        } else {
            resolved_base = base_url;
            if (resolved_base.empty()) {
                res.set_content(R"({"error":"Unknown service"})", "application/json");
                res.status = 400;
                return;
            }
        }

        std::string full_url = resolved_base + path;
        auto [status, content] = do_http_get(full_url);
        if (status < 0) {
            res.set_content(R"({"error":"Proxy request failed"})", "application/json");
            res.status = 502;
            return;
        }

        json resp = {{"status", status}, {"body", content.substr(0, 5000)}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"healthy","service":"gateway-api"})", "application/json");
    });

    printf("Gateway API running on port 9011\n");
    svr.listen("0.0.0.0", 9011);
    return 0;
}
