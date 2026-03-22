#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <ctime>
#include <cstdlib>
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
    int failed_attempts;
};

struct SessionData {
    int user_id;
    time_t created;
};

static const std::string DB_HOST = "db.internal.acmecorp.io";
static const std::string DB_USER = "appuser";
static const std::string DB_PASS = "Pg_Pr0d#2024";
static const std::string SMTP_HOST = "mail.internal.acmecorp.io";
static const std::string SMTP_PASS = "SmtpR3lay#2024!";

static std::unordered_map<int, User> users;
static std::unordered_map<std::string, SessionData> sessions;
static std::unordered_map<std::string, int> reset_tokens;
static std::mutex data_mutex;
static int next_user_id = 5;

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
    users[1] = {1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", true, 0};
    users[2] = {2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", true, 0};
    users[3] = {3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", true, 0};
    users[4] = {4, "bwilson", "bwilson@acmecorp.io", "B0b_W1ls0n", "analyst", false, 0};
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
                    json resp = {{"error", "Account '" + username + "' is deactivated. Contact admin@acmecorp.io."}};
                    res.set_content(resp.dump(), "application/json");
                    return;
                }

                if (user.password == password) {
                    user.failed_attempts = 0;
                    std::string token = create_session(uid);
                    json resp = {{"token", token}, {"user_id", uid}, {"role", user.role}};
                    res.set_content(resp.dump(), "application/json");
                    return;
                }

                user.failed_attempts++;
                json resp = {{"error", "Incorrect password"}, {"attempts", user.failed_attempts}};
                res.status = 401;
                res.set_content(resp.dump(), "application/json");
                return;
            }
        }

        res.status = 404;
        json resp = {{"error", "No account found for username '" + username + "'"}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/register", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content("{\"error\":\"Request body required\"}", "application/json");
            return;
        }

        std::string username = body.value("username", "");
        std::string email = body.value("email", "");
        std::string password = body.value("password", "");

        if (username.empty() || email.empty() || password.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"All fields required\"}", "application/json");
            return;
        }

        for (auto& [uid, user] : users) {
            if (user.username == username) {
                res.status = 409;
                json resp = {{"error", "Username '" + username + "' is already taken"}};
                res.set_content(resp.dump(), "application/json");
                return;
            }
            if (user.email == email) {
                res.status = 409;
                json resp = {{"error", "Email '" + email + "' is already registered"}};
                res.set_content(resp.dump(), "application/json");
                return;
            }
        }

        int new_id = next_user_id++;
        users[new_id] = {new_id, username, email, password, "viewer", true, 0};
        json resp = {{"message", "User registered"}, {"user_id", new_id}};
        res.status = 201;
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/password-reset", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto body = json::parse(req.body, nullptr, false);
        std::string email = body.value("email", "");

        for (auto& [uid, user] : users) {
            if (user.email == email) {
                std::string raw = email + std::to_string(time(nullptr));
                std::string token = simple_hash(raw).substr(0, 16);
                reset_tokens[token] = uid;

                json resp = {
                    {"message", "Password reset link sent"},
                    {"token", token},
                    {"smtp_server", SMTP_HOST}
                };
                res.set_content(resp.dump(), "application/json");
                return;
            }
        }

        res.status = 404;
        json resp = {{"error", "No account associated with '" + email + "'"}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/password-reset/confirm", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto body = json::parse(req.body, nullptr, false);
        std::string token = body.value("token", "");
        std::string new_password = body.value("new_password", "");

        auto it = reset_tokens.find(token);
        if (it == reset_tokens.end()) {
            res.status = 400;
            res.set_content("{\"error\":\"Invalid or expired token\"}", "application/json");
            return;
        }

        auto uit = users.find(it->second);
        if (uit != users.end()) {
            uit->second.password = new_password;
            reset_tokens.erase(it);
            res.set_content("{\"message\":\"Password updated successfully\"}", "application/json");
            return;
        }

        res.status = 404;
        res.set_content("{\"error\":\"User not found\"}", "application/json");
    });

    svr.Put("/api/users/me/password", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string new_password = body.value("new_password", "");
        if (new_password.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"New password required\"}", "application/json");
            return;
        }

        auto it = users.find(uid);
        if (it == users.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"User not found\"}", "application/json");
            return;
        }

        it->second.password = new_password;
        res.set_content("{\"message\":\"Password updated\"}", "application/json");
    });

    svr.Get("/api/users/me", [](const httplib::Request& req, httplib::Response& res) {
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

        json resp = {
            {"id", it->second.id}, {"username", it->second.username},
            {"email", it->second.email}, {"role", it->second.role}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/reports/generate", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string report_type = body.value("type", "");

        res.status = 500;
        json resp = {
            {"error", "Report generation failed"},
            {"details", "Could not connect to database at " + DB_HOST + " as user '" + DB_USER + "' with password '" + DB_PASS + "'"},
            {"report_type", report_type}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/config", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int uid = get_session_user(req);
        if (uid < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        auto it = users.find(uid);
        if (it == users.end() || it->second.role != "admin") {
            res.status = 403;
            res.set_content("{\"error\":\"Admin access required\"}", "application/json");
            return;
        }

        json resp = {
            {"database_host", DB_HOST}, {"database_user", DB_USER}, {"database_password", DB_PASS},
            {"smtp_host", SMTP_HOST}, {"smtp_password", SMTP_PASS},
            {"session_count", sessions.size()}, {"user_count", users.size()}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get(R"(/api/debug/user/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int caller = get_session_user(req);
        if (caller < 0) {
            res.status = 401;
            res.set_content("{\"error\":\"Authentication required\"}", "application/json");
            return;
        }

        int target_id = std::stoi(req.matches[1]);
        auto it = users.find(target_id);
        if (it == users.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"User not found\"}", "application/json");
            return;
        }

        json resp = {
            {"id", it->second.id}, {"username", it->second.username},
            {"email", it->second.email}, {"password", it->second.password},
            {"role", it->second.role}, {"active", it->second.active},
            {"failed_attempts", it->second.failed_attempts}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"status\":\"healthy\",\"service\":\"design-api\"}", "application/json");
    });

    printf("Design Service API running on port 9187\n");
    svr.listen("0.0.0.0", 9187);
    return 0;
}
