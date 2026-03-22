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
#include <atomic>
#include <cstring>

using json = nlohmann::json;

static const std::string SIGNING_SECRET = "platform-sign-key-2024";
static const unsigned char DES_KEY[8] = {'s','3','c','r','3','t','!','!'};

struct User {
    int id;
    std::string username;
    std::string email;
    std::string password_hash;
    std::string role;
    bool active;
    std::string hash_algo;
};

struct SessionData {
    int user_id;
};

struct EncryptedRecord {
    int id;
    std::string encrypted_content;
    std::string signature;
    int owner_id;
};

struct TokenData {
    std::string label;
    int owner_id;
};

static std::mutex data_mutex;
static std::unordered_map<int, User> users;
static std::unordered_map<std::string, SessionData> sessions;
static std::unordered_map<int, EncryptedRecord> records;
static std::unordered_map<std::string, TokenData> api_tokens;
static std::atomic<int> record_counter{0};
static std::atomic<int> token_seq{6000};

static std::string md5_hash(const std::string& input) {
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h;
    std::string result = oss.str();
    std::hash<std::string> hasher2;
    size_t h2 = hasher2(input + "x");
    std::ostringstream oss2;
    oss2 << std::hex << std::setfill('0') << std::setw(16) << h2;
    return result + oss2.str();
}

static std::string sha1_hash(const std::string& input) {
    std::hash<std::string> hasher;
    size_t h1 = hasher(input);
    size_t h2 = hasher(input + "sha1salt");
    size_t h3 = h1 ^ (h2 << 1);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(16) << h1
        << std::setw(16) << h2
        << std::setw(8) << (h3 & 0xFFFFFFFF);
    return oss.str();
}

static std::string des_xor_encrypt(const std::string& plaintext) {
    size_t len = plaintext.size();
    size_t pad_len = 8 - (len % 8);
    std::string padded = plaintext + std::string(pad_len, static_cast<char>(pad_len));

    std::string encrypted(padded.size(), '\0');
    for (size_t i = 0; i < padded.size(); i++) {
        encrypted[i] = padded[i] ^ DES_KEY[i % 8];
    }

    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (size_t i = 0; i < encrypted.size(); i += 3) {
        unsigned int n = (static_cast<unsigned char>(encrypted[i])) << 16;
        if (i + 1 < encrypted.size()) n |= (static_cast<unsigned char>(encrypted[i + 1])) << 8;
        if (i + 2 < encrypted.size()) n |= static_cast<unsigned char>(encrypted[i + 2]);
        result += b64[(n >> 18) & 0x3F];
        result += b64[(n >> 12) & 0x3F];
        result += (i + 1 < encrypted.size()) ? b64[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < encrypted.size()) ? b64[n & 0x3F] : '=';
    }
    return result;
}

static std::string des_xor_decrypt(const std::string& ciphertext) {
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

    size_t in_len = ciphertext.size();
    size_t data_len = (in_len / 4) * 3;
    if (in_len > 0 && ciphertext[in_len - 1] == '=') data_len--;
    if (in_len > 1 && ciphertext[in_len - 2] == '=') data_len--;

    std::string data(data_len, '\0');
    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        unsigned int n = 0;
        for (int k = 0; k < 4; k++) {
            n <<= 6;
            if (ciphertext[i + k] != '=')
                n |= b64_inv[static_cast<int>(ciphertext[i + k])];
        }
        if (j < data_len) data[j++] = (n >> 16) & 0xFF;
        if (j < data_len) data[j++] = (n >> 8) & 0xFF;
        if (j < data_len) data[j++] = n & 0xFF;
    }

    std::string decrypted(data_len, '\0');
    for (size_t i = 0; i < data_len; i++) {
        decrypted[i] = data[i] ^ DES_KEY[i % 8];
    }

    if (!decrypted.empty()) {
        size_t pad = static_cast<unsigned char>(decrypted.back());
        if (pad <= 8 && pad <= decrypted.size()) {
            decrypted.resize(decrypted.size() - pad);
        }
    }
    return decrypted;
}

static std::string compute_signature(const std::string& data) {
    return md5_hash(data + SIGNING_SECRET);
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

static std::string generate_api_token() {
    int seq = token_seq.fetch_add(1);
    long ts = static_cast<long>(time(nullptr));
    std::string raw = "tkn-" + std::to_string(seq) + "-" + std::to_string(ts);
    return sha1_hash(raw).substr(0, 24);
}

static void init_data() {
    users[1] = {1, "admin", "admin@cipherguard.io", md5_hash("admin2024!"), "admin", true, "md5"};
    users[2] = {2, "sgarcia", "sgarcia@cipherguard.io", md5_hash("sofia_g99"), "manager", true, "md5"};
    users[3] = {3, "tpatel", "tpatel@cipherguard.io", sha1_hash("tara_p!"), "analyst", true, "sha1"};
    users[4] = {4, "jlee", "jlee@cipherguard.io", md5_hash("jake_view"), "viewer", false, "md5"};
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

        std::lock_guard<std::mutex> lock(data_mutex);
        for (auto& [id, user] : users) {
            if (user.username == username) {
                std::string provided_hash;
                if (user.hash_algo == "sha1") {
                    provided_hash = sha1_hash(password);
                } else {
                    provided_hash = md5_hash(password);
                }
                if (provided_hash == user.password_hash) {
                    std::string token = generate_token();
                    sessions[token] = {id};
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

    svr.Post("/api/records", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        SessionData* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string content = body.value("content", "");
        if (content.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"Content required"})", "application/json");
            return;
        }

        int id = record_counter.fetch_add(1) + 1;
        std::string encrypted = des_xor_encrypt(content);
        std::string sig = compute_signature(content);

        records[id] = {id, encrypted, sig, sess->user_id};
        json resp = {{"id", id}, {"signature", sig}, {"message", "Record encrypted and stored"}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get(R"(/api/records/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        SessionData* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        int record_id = std::stoi(req.matches[1]);
        auto it = records.find(record_id);
        if (it == records.end()) {
            res.status = 404;
            res.set_content(R"({"error":"Record not found"})", "application/json");
            return;
        }

        std::string decrypted = des_xor_decrypt(it->second.encrypted_content);
        json resp = {{"id", it->second.id}, {"content", decrypted},
                     {"signature", it->second.signature}, {"ownerId", it->second.owner_id}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/tokens/generate", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        SessionData* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string label = body.is_discarded() ? "default" : body.value("label", "default");

        std::string token = generate_api_token();
        api_tokens[token] = {label, sess->user_id};

        json resp = {{"token", token}, {"label", label}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/tokens/validate", [](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body, nullptr, false);
        std::string token = body.value("token", "");

        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = api_tokens.find(token);
        if (it != api_tokens.end()) {
            json resp = {{"valid", true}, {"label", it->second.label}, {"ownerId", it->second.owner_id}};
            res.set_content(resp.dump(), "application/json");
            return;
        }

        res.status = 401;
        res.set_content(R"({"valid":false})", "application/json");
    });

    svr.Post("/api/hash", [](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body, nullptr, false);
        std::string value = body.value("value", "");
        if (value.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"Value required"})", "application/json");
            return;
        }

        std::string algorithm = body.value("algorithm", "md5");
        std::string result;
        if (algorithm == "sha1") {
            result = sha1_hash(value);
        } else {
            result = md5_hash(value);
        }

        json resp = {{"hash", result}, {"algorithm", algorithm}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/encrypt", [](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body, nullptr, false);
        std::string plaintext = body.value("plaintext", "");
        if (plaintext.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"Plaintext required"})", "application/json");
            return;
        }

        std::string encrypted = des_xor_encrypt(plaintext);
        json resp = {{"ciphertext", encrypted}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Post("/api/decrypt", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        SessionData* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string ciphertext = body.value("ciphertext", "");
        if (ciphertext.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"Ciphertext required"})", "application/json");
            return;
        }

        std::string decrypted = des_xor_decrypt(ciphertext);
        json resp = {{"plaintext", decrypted}};
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
                {"id", u.id}, {"username", u.username}, {"email", u.email},
                {"role", u.role}, {"active", u.active}
            });
        }
        res.set_content(json{{"users", user_list}}.dump(), "application/json");
    });

    svr.Put("/api/users/me/password", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        SessionData* sess = get_session(req);
        if (!sess) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return;
        }

        auto body = json::parse(req.body, nullptr, false);
        std::string new_password = body.value("newPassword", "");
        if (new_password.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"New password required"})", "application/json");
            return;
        }

        auto it = users.find(sess->user_id);
        if (it == users.end()) {
            res.status = 404;
            res.set_content(R"({"error":"User not found"})", "application/json");
            return;
        }

        it->second.password_hash = md5_hash(new_password);
        res.set_content(R"({"message":"Password updated"})", "application/json");
    });

    printf("CipherGuard Crypto API running on port 8101\n");
    svr.listen("0.0.0.0", 8101);
    return 0;
}
