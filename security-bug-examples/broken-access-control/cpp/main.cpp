#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdlib>
#include <mutex>

using json = nlohmann::json;

struct User {
    int id;
    std::string username;
    std::string email;
    std::string role;
    std::string ssn;
    int salary;
    std::string department;
};

struct Asset {
    int id;
    int owner_id;
    std::string name;
    std::string serial_number;
    std::string location;
    std::string status;
    double value;
};

struct Session {
    int user_id;
    std::string role;
};

static std::mutex data_mutex;
static std::unordered_map<int, User> users;
static std::unordered_map<int, Asset> assets;
static std::unordered_map<std::string, Session> sessions;

void init_data() {
    users[1] = {1, "alice", "alice@inventory.io", "admin", "123-45-6789", 135000, "operations"};
    users[2] = {2, "bob", "bob@inventory.io", "manager", "987-65-4321", 98000, "warehouse"};
    users[3] = {3, "charlie", "charlie@inventory.io", "staff", "555-12-3456", 62000, "warehouse"};
    users[4] = {4, "diana", "diana@inventory.io", "staff", "444-33-2211", 60000, "logistics"};

    assets[601] = {601, 1, "Server Rack A", "SRV-2024-001", "Data Center Room 3",
                   "active", 45000.00};
    assets[602] = {602, 2, "Forklift #7", "FLT-2023-007", "Warehouse B",
                   "active", 32000.00};
    assets[603] = {603, 3, "Laptop Dell XPS", "LPT-2024-042", "Office 201",
                   "assigned", 1800.00};
    assets[604] = {604, 1, "Network Switch", "NSW-2024-003", "Data Center Room 3",
                   "active", 8500.00};

    sessions["tok_alice"] = {1, "admin"};
    sessions["tok_bob"] = {2, "manager"};
    sessions["tok_charlie"] = {3, "staff"};
    sessions["tok_diana"] = {4, "staff"};
}

Session* get_session(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return nullptr;
    std::string auth = it->second;
    if (auth.substr(0, 7) != "Bearer ") return nullptr;
    std::string token = auth.substr(7);
    auto sit = sessions.find(token);
    if (sit == sessions.end()) return nullptr;
    return &sit->second;
}

json user_to_json(const User& u) {
    return json{
        {"id", u.id}, {"username", u.username}, {"email", u.email},
        {"role", u.role}, {"ssn", u.ssn}, {"salary", u.salary},
        {"department", u.department}
    };
}

json asset_to_json(const Asset& a) {
    return json{
        {"id", a.id}, {"owner_id", a.owner_id}, {"name", a.name},
        {"serial_number", a.serial_number}, {"location", a.location},
        {"status", a.status}, {"value", a.value}
    };
}

int main() {
    init_data();
    httplib::Server svr;

    svr.Get(R"(/api/users/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        int user_id = std::stoi(req.matches[1]);
        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = users.find(user_id);
        if (it == users.end()) {
            res.status = 404;
            res.set_content(R"({"error":"User not found"})", "application/json");
            return;
        }
        res.set_content(user_to_json(it->second).dump(), "application/json");
    });

    svr.Get(R"(/api/assets/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        Session* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        int asset_id = std::stoi(req.matches[1]);
        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = assets.find(asset_id);
        if (it == assets.end()) {
            res.status = 404;
            res.set_content(R"({"error":"Asset not found"})", "application/json");
            return;
        }
        res.set_content(asset_to_json(it->second).dump(), "application/json");
    });

    svr.Put(R"(/api/assets/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        Session* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        int asset_id = std::stoi(req.matches[1]);
        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = assets.find(asset_id);
        if (it == assets.end()) {
            res.status = 404;
            res.set_content(R"({"error":"Asset not found"})", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(R"({"error":"Invalid JSON"})", "application/json");
            return;
        }

        Asset& asset = it->second;
        if (body.contains("name")) asset.name = body["name"].get<std::string>();
        if (body.contains("location")) asset.location = body["location"].get<std::string>();
        if (body.contains("status")) asset.status = body["status"].get<std::string>();
        if (body.contains("value")) asset.value = body["value"].get<double>();

        json resp = {{"message", "Asset updated"}, {"asset", asset_to_json(asset)}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/admin/users", [](const httplib::Request& req, httplib::Response& res) {
        Session* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        auto it = req.headers.find("X-User-Role");
        std::string client_role = (it != req.headers.end()) ? it->second : "";
        if (client_role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }

        std::lock_guard<std::mutex> lock(data_mutex);
        json user_list = json::array();
        for (auto& [id, u] : users) {
            user_list.push_back(user_to_json(u));
        }
        res.set_content(json{{"users", user_list}}.dump(), "application/json");
    });

    svr.Put(R"(/api/users/(\d+)/role)", [](const httplib::Request& req, httplib::Response& res) {
        Session* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        int user_id = std::stoi(req.matches[1]);
        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = users.find(user_id);
        if (it == users.end()) {
            res.status = 404;
            res.set_content(R"({"error":"User not found"})", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string new_role = "staff";
        if (!body.is_discarded() && body.contains("role")) {
            new_role = body["role"].get<std::string>();
        }
        it->second.role = new_role;

        json resp = {{"message", "Role updated"}, {"userId", user_id}, {"newRole", new_role}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/debug/config", [](const httplib::Request& req, httplib::Response& res) {
        const char* db_url = std::getenv("DATABASE_URL");
        const char* secret = std::getenv("APP_SECRET");
        const char* aws_key = std::getenv("AWS_ACCESS_KEY");
        const char* aws_secret = std::getenv("AWS_SECRET_KEY");

        json config = {
            {"databaseUrl", db_url ? db_url : "postgres://admin:s3cret@db:5432/inventorydb"},
            {"appSecret", secret ? secret : "inventory-api-secret-key"},
            {"awsCredentials", {
                {"accessKey", aws_key ? aws_key : "AKIAIOSFODNN7EXAMPLE"},
                {"secretKey", aws_secret ? aws_secret : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
            }},
            {"serverPort", 8091}
        };
        res.set_content(config.dump(), "application/json");
    });

    printf("Asset Inventory API running on port 8091\n");
    svr.listen("0.0.0.0", 8091);
    return 0;
}
