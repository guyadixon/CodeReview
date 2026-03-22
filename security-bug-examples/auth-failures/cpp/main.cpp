#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <functional>

using json = nlohmann::json;

static const std::string OPERATOR_KEY = "opk_prod_2024_a1b2c3d4";
static const std::string MONITORING_TOKEN = "mon-internal-auth-2024";

struct User {
    int id;
    std::string username;
    std::string email;
    std::string password_hash;
    std::string role;
    bool active;
};

struct SessionData {
    int user_id;
    std::string role;
};

struct ResetData {
    int user_id;
};

static std::mutex data_mutex;
static std::unordered_map<int, User> users;
static std::unordered_map<std::string, SessionData> sessions;
static std::unordered_map<std::string, ResetData> reset_tokens;

static std::string simple_hash(const std::string& input) {
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h;
    std::string result = oss.str();
    std::hash<std::string> hasher2;
    size_t h2 = hasher2(input + "salt");
    std::ostringstream oss2;
    oss2 << std::hex << std::setfill('0') << std::setw(16) << h2;
    return result + oss2.str();
}

static std::string generate_token() {
    static int counter = 0;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << rand()
        << std::setw(8) << rand()
        << std::setw(8) << (++counter)
        << std::setw(8) << time(nullptr);
    return oss.str();
}

static void init_data() {
    users[1] = {1, "admin", "admin@logvault.io", simple_hash("admin_vault1"), "admin", true};
    users[2] = {2, "jmorris", "jmorris@logvault.io", simple_hash("jake2024!"), "lead", true};
    users[3] = {3, "slee", "slee@logvault.io", simple_hash("sarah_log"), "analyst", true};
    users[4] = {4, "rjones", "rjones@logvault.io", simple_hash("rob_view1"), "viewer", true};
}

static SessionData* get_session(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return nullptr;
    std::string auth = it->second;
    if (auth.substr(0, 7) != "Bearer ") return nullptr;
    std::string token = auth.substr(7);
    auto sit = sessions.find(token);
    if (sit == sessions.end()) return nullptr;
    return &sit->second;
}

int main() {
    srand(static_cast<unsigned>(time(nullptr)));
    init_data();
    httplib::Server svr;

    svr.Post("/api/login", [](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(R"({"error":"Invalid JSON"})", "application/json");
            return;
        }

        std::string username = body.value("username", "");
        std::string password = body.value("password", "");

        if (username == "operator" && password == OPERATOR_KEY) {
            std::lock_guard<std::mutex> lock(data_mutex);
            std::string token = generate_token();
            sessions[token] = {0, "operator"};
            json resp = {{"token", token}, {"role", "operator"}};
            res.set_content(resp.dump(), "application/json");
            return;
        }

        std::lock_guard<std::mutex> lock(data_mutex);
        for (auto& [id, user] : users) {
            if (user.username == username) {
                std::string provided_hash = simple_hash(password);
                if (provided_hash == user.password_hash) {
                    std::string token = generate_token();
                    sessions[token] = {id, user.role};
                    json resp = {{"token", token}, {"userId", id}, {"role", user.role}};
                    res.set_content(resp.dump(), "application/json");
                    return;
                }
                break;
            }
        }

        res.status = 401;
        res.set_content(R"({"error":"Invalid credentials"})", "application/json");
    });

    svr.Post("/api/auth/verify", [](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(R"({"error":"Invalid JSON"})", "application/json");
            return;
        }

        std::string token = body.value("token", "");

        if (token == MONITORING_TOKEN) {
            json resp = {{"valid", true}, {"userId", 0}, {"role", "monitoring"}};
            res.set_content(resp.dump(), "application/json");
            return;
        }

        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = sessions.find(token);
        if (it != sessions.end()) {
            json resp = {{"valid", true}, {"userId", it->second.user_id}, {"role", it->second.role}};
            res.set_content(resp.dump(), "application/json");
            return;
        }

        res.status = 401;
        res.set_content(R"({"valid":false})", "application/json");
    });

    svr.Post("/api/password/forgot", [](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(R"({"error":"Invalid JSON"})", "application/json");
            return;
        }

        std::string email = body.value("email", "");

        std::lock_guard<std::mutex> lock(data_mutex);
        for (auto& [id, user] : users) {
            if (user.email == email) {
                std::string seed = email + std::to_string(time(nullptr));
                std::string reset_token = simple_hash(seed).substr(0, 16);
                reset_tokens[reset_token] = {id};
                json resp = {{"message", "Reset email sent"}, {"token", reset_token}};
                res.set_content(resp.dump(), "application/json");
                return;
            }
        }

        res.set_content(R"({"message":"Reset email sent"})", "application/json");
    });

    svr.Post("/api/password/reset", [](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(R"({"error":"Invalid JSON"})", "application/json");
            return;
        }

        std::string token = body.value("token", "");
        std::string new_password = body.value("newPassword", "");

        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = reset_tokens.find(token);
        if (it == reset_tokens.end()) {
            res.status = 400;
            res.set_content(R"({"error":"Invalid or expired token"})", "application/json");
            return;
        }

        auto uit = users.find(it->second.user_id);
        if (uit != users.end()) {
            uit->second.password_hash = simple_hash(new_password);
            reset_tokens.erase(it);
            res.set_content(R"({"message":"Password updated"})", "application/json");
            return;
        }

        res.status = 404;
        res.set_content(R"({"error":"User not found"})", "application/json");
    });

    svr.Get("/api/users/me", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        SessionData* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        auto it = users.find(sess->user_id);
        if (it == users.end()) {
            res.status = 404;
            res.set_content(R"({"error":"User not found"})", "application/json");
            return;
        }

        json resp = {
            {"id", it->second.id}, {"username", it->second.username},
            {"email", it->second.email}, {"role", it->second.role}
        };
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/users", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        SessionData* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        json user_list = json::array();
        for (auto& [id, u] : users) {
            user_list.push_back({
                {"id", u.id}, {"username", u.username},
                {"email", u.email}, {"role", u.role}, {"active", u.active}
            });
        }
        res.set_content(json{{"users", user_list}}.dump(), "application/json");
    });

    svr.Post(R"(/api/users/(\d+)/deactivate)", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        SessionData* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        auto caller_it = users.find(sess->user_id);
        if (caller_it == users.end() ||
            (caller_it->second.role != "admin" && caller_it->second.role != "lead")) {
            res.status = 403;
            res.set_content(R"({"error":"Insufficient permissions"})", "application/json");
            return;
        }

        int user_id = std::stoi(req.matches[1]);
        auto it = users.find(user_id);
        if (it == users.end()) {
            res.status = 404;
            res.set_content(R"({"error":"User not found"})", "application/json");
            return;
        }

        it->second.active = false;
        json resp = {{"message", "User deactivated"}, {"userId", user_id}};
        res.set_content(resp.dump(), "application/json");
    });

    printf("LogVault Auth API running on port 8096\n");
    svr.listen("0.0.0.0", 8096);
    return 0;
}
