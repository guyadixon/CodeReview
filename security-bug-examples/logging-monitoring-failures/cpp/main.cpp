#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <ctime>
#include <functional>
#include <mutex>
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
    bool mfa_enabled;
    std::string api_key;
};

struct SessionData {
    int user_id;
    time_t created;
};

struct Transaction {
    int id;
    int user_id;
    double amount;
    std::string recipient;
    std::string description;
    time_t timestamp;
    std::string status;
};

static std::unordered_map<int, User> users;
static std::unordered_map<std::string, SessionData> sessions;
static std::vector<Transaction> transactions;
static std::mutex data_mutex;
static int next_tx_id = 1;

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
    sessions[token] = {user_id, time(nullptr)};
    return token;
}

static int get_session_user(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it != req.headers.end() && it->second.substr(0, 7) == "Bearer ") {
        std::string token = it->second.substr(7);
        auto sit = sessions.find(token);
        if (sit != sessions.end()) return sit->second.user_id;
    }
    return -1;
}

static void init_data() {
    users[1] = {1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", true, true, "ak-admin-x7k9m2"};
    users[2] = {2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", true, false, "ak-jdoe-p3q8r1"};
    users[3] = {3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", true, false, "ak-asmith-w5t6y4"};
    users[4] = {4, "bwilson", "bwilson@acmecorp.io", "B0b_W1ls0n", "analyst", false, false, "ak-bwilson-z2v8n3"};
}

int main() {
    init_data();
    httplib::Server svr;

    svr.Post("/api/login", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content("{\"error\":\"Request body required\"}", "application/json");
            return;
        }

        std::string username = body.value("username", "");
        std::string password = body.value("password", "");

        for (auto& [uid, user] : users) {
            if (user.username == username) {
                if (!user.active) {
                    res.status = 403;
                    res.set_content("{\"error\":\"Account disabled\"}", "application/json");
                    return;
                }

                if (user.password == password) {
                    std::string token = create_session(uid);
                    json resp = {
                        {"token", token}, {"user_id", uid}, {"role", user.role},
                        {"password", user.password}, {"api_key", user.api_key}
                    };
                    res.set_content(resp.dump(), "application/json");
                    return;
                }

                res.status = 401;
                res.set_content("{\"error\":\"Invalid credentials\"}", "application/json");
                return;
            }
        }

        res.status = 401;
        res.set_content("{\"error\":\"Invalid credentials\"}", "application/json");
    });

    svr.Get("/api/admin/users", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        json result = json::array();
        for (auto& [id, user] : users) {
            result.push_back({
                {"id", user.id}, {"username", user.username}, {"email", user.email},
                {"role", user.role}, {"active", user.active}
            });
        }
        res.set_content(json{{"users", result}}.dump(), "application/json");
    });

    svr.Put(R"(/api/admin/users/(\d+)/role)", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int caller_id = get_session_user(req);
        if (caller_id < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        int target_id = std::stoi(req.matches[1]);
        auto it = users.find(target_id);
        if (it == users.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"Target user not found\"}", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string new_role = body.value("role", "");
        std::string old_role = it->second.role;
        it->second.role = new_role;

        json resp = {
            {"message", "Role updated"}, {"user_id", target_id},
            {"old_role", old_role}, {"new_role", new_role}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post(R"(/api/admin/users/(\d+)/deactivate)", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int caller_id = get_session_user(req);
        if (caller_id < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto caller = users.find(caller_id);
        if (caller == users.end() || caller->second.role != "admin") {
            res.status = 403;
            res.set_content("{\"error\":\"Admin access required\"}", "application/json");
            return;
        }

        int target_id = std::stoi(req.matches[1]);
        auto it = users.find(target_id);
        if (it == users.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"Target user not found\"}", "application/json");
            return;
        }

        it->second.active = false;
        json resp = {{"message", "User deactivated"}, {"user_id", target_id}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/transactions", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string recipient = body.value("recipient", "");
        if (recipient.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"Recipient required\"}", "application/json");
            return;
        }

        Transaction tx;
        tx.id = next_tx_id++;
        tx.user_id = uid;
        tx.amount = body.value("amount", 0.0);
        tx.recipient = recipient;
        tx.description = body.value("description", "");
        tx.timestamp = time(nullptr);
        tx.status = "completed";
        transactions.push_back(tx);

        json resp = {
            {"message", "Transaction completed"},
            {"transaction", {
                {"id", tx.id}, {"user_id", tx.user_id}, {"amount", tx.amount},
                {"recipient", tx.recipient}, {"status", tx.status}
            }}
        };
        res.status = 201;
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/transactions/bulk", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        auto transfers = body.value("transfers", json::array());

        json results = json::array();
        for (auto& t : transfers) {
            Transaction tx;
            tx.id = next_tx_id++;
            tx.user_id = uid;
            tx.amount = t.value("amount", 0.0);
            tx.recipient = t.value("recipient", "");
            tx.description = t.value("description", "");
            tx.timestamp = time(nullptr);
            tx.status = "completed";
            transactions.push_back(tx);
            results.push_back({
                {"id", tx.id}, {"user_id", tx.user_id}, {"amount", tx.amount},
                {"recipient", tx.recipient}, {"status", tx.status}
            });
        }

        json resp = {
            {"message", std::to_string(results.size()) + " transfers completed"},
            {"transactions", results}
        };
        res.status = 201;
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/export/data", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string export_type = body.value("type", "");

        if (export_type == "users") {
            json export_data = json::array();
            for (auto& [id, u] : users) {
                export_data.push_back({
                    {"id", u.id}, {"username", u.username}, {"email", u.email},
                    {"password", u.password}, {"api_key", u.api_key}, {"role", u.role}
                });
            }
            res.set_content(json{{"export", export_data}}.dump(), "application/json");
            return;
        }

        if (export_type == "transactions") {
            json export_data = json::array();
            for (auto& tx : transactions) {
                export_data.push_back({
                    {"id", tx.id}, {"user_id", tx.user_id}, {"amount", tx.amount},
                    {"recipient", tx.recipient}, {"status", tx.status}
                });
            }
            res.set_content(json{{"export", export_data}}.dump(), "application/json");
            return;
        }

        res.status = 400;
        res.set_content("{\"error\":\"Unknown export type\"}", "application/json");
    });

    svr.Post("/api/settings/api-key", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto it = users.find(uid);
        if (it == users.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"User not found\"}", "application/json");
            return;
        }

        std::string old_key = it->second.api_key;
        std::string raw = it->second.username + std::to_string(time(nullptr));
        std::string new_key = "ak-" + simple_hash(raw).substr(0, 12);
        it->second.api_key = new_key;

        json resp = {
            {"message", "API key regenerated"},
            {"old_key", old_key}, {"new_key", new_key}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Put("/api/settings/mfa", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto it = users.find(uid);
        if (it == users.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"User not found\"}", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        bool enabled = body.value("enabled", false);
        it->second.mfa_enabled = enabled;

        json resp = {{"message", "MFA setting updated"}, {"mfa_enabled", enabled}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/validate-key", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto body = json::parse(req.body, nullptr, false);
        std::string api_key = body.value("api_key", "");

        for (auto& [id, user] : users) {
            if (user.api_key == api_key) {
                json resp = {
                    {"valid", true}, {"user_id", user.id},
                    {"username", user.username}, {"role", user.role}
                };
                res.set_content(resp.dump(), "application/json");
                return;
            }
        }

        res.status = 401;
        res.set_content("{\"valid\":false}", "application/json");
    });

    svr.Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"status\":\"healthy\",\"service\":\"logging-api\"}", "application/json");
    });

    printf("Logging Monitor API running on port 9189\n");
    svr.listen("0.0.0.0", 9189);
    return 0;
}
