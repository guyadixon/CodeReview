#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <mutex>
#include <atomic>
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;

struct Product {
    int id;
    std::string name;
    double price;
    int stock;
    std::string category;
};

struct OrderItem {
    int product_id;
    std::string name;
    int quantity;
    double subtotal;
};

struct Order {
    int id;
    std::vector<OrderItem> items;
    double total;
    std::string status;
    std::string customer_email;
};

static std::unordered_map<int, Product> products;
static std::unordered_map<int, Order> orders;
static std::mutex data_mutex;
static std::atomic<int> order_counter{1000};

static const std::string WAREHOUSE_ENDPOINT = "https://warehouse.internal.acmecorp.io/api/v2";

static double round2(double v) {
    return std::round(v * 100.0) / 100.0;
}

static void init_data() {
    products[1] = {1, "Widget Pro", 29.99, 150, "hardware"};
    products[2] = {2, "Gadget Plus", 49.99, 75, "electronics"};
    products[3] = {3, "Tool Kit Standard", 19.99, 200, "tools"};
    products[4] = {4, "Sensor Array", 89.99, 30, "electronics"};
    products[5] = {5, "Cable Bundle", 9.99, 500, "accessories"};
}

int main() {
    init_data();
    httplib::Server svr;

    svr.Get("/api/products", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        std::string category = req.get_param_value("category");

        json arr = json::array();
        for (auto& [id, p] : products) {
            if (!category.empty() && p.category != category) continue;
            arr.push_back({{"id", p.id}, {"name", p.name}, {"price", p.price},
                           {"stock", p.stock}, {"category", p.category}});
        }
        json result = {{"products", arr}, {"total", arr.size()}};
        res.set_content(result.dump(), "application/json");
    });

    svr.Get(R"(/api/products/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int pid = std::stoi(req.matches[1]);
        auto it = products.find(pid);
        if (it == products.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"Product not found\"}", "application/json");
            return;
        }
        auto& p = it->second;
        json obj = {{"id", p.id}, {"name", p.name}, {"price", p.price},
                    {"stock", p.stock}, {"category", p.category}};
        res.set_content(obj.dump(), "application/json");
    });

    svr.Post("/api/orders", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("items") || !body["items"].is_array()
            || body["items"].empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"At least one item required\"}", "application/json");
            return;
        }

        std::vector<OrderItem> order_items;
        double total = 0.0;

        for (auto& item : body["items"]) {
            int pid = item.value("product_id", 0);
            int qty = item.value("quantity", 1);
            if (qty <= 0) qty = 1;

            auto pit = products.find(pid);
            if (pit == products.end()) {
                res.status = 404;
                json resp = {{"error", "Product " + std::to_string(pid) + " not found"}};
                res.set_content(resp.dump(), "application/json");
                return;
            }

            auto& p = pit->second;
            if (p.stock < qty) {
                res.status = 400;
                json resp = {{"error", "Insufficient stock for " + p.name}};
                res.set_content(resp.dump(), "application/json");
                return;
            }

            p.stock -= qty;
            double subtotal = round2(p.price * qty);
            total += subtotal;
            order_items.push_back({pid, p.name, qty, subtotal});
        }

        int oid = ++order_counter;
        orders[oid] = {oid, order_items, round2(total), "confirmed",
                       body.value("email", "")};

        json resp = {{"order_id", oid}, {"total", round2(total)}, {"status", "confirmed"}};
        res.status = 201;
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get(R"(/api/orders/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int oid = std::stoi(req.matches[1]);
        auto it = orders.find(oid);
        if (it == orders.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"Order not found\"}", "application/json");
            return;
        }

        auto& o = it->second;
        json items_arr = json::array();
        for (auto& oi : o.items) {
            items_arr.push_back({{"product_id", oi.product_id}, {"name", oi.name},
                                 {"quantity", oi.quantity}, {"subtotal", oi.subtotal}});
        }

        json obj = {{"id", o.id}, {"items", items_arr}, {"total", o.total},
                    {"status", o.status}, {"customer_email", o.customer_email}};
        res.set_content(obj.dump(), "application/json");
    });

    svr.Post("/api/inventory/import", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("payload")) {
            res.status = 400;
            res.set_content("{\"error\":\"Payload required\"}", "application/json");
            return;
        }

        auto payload = body["payload"];
        if (!payload.contains("products") || !payload["products"].is_array()) {
            res.status = 400;
            res.set_content("{\"error\":\"Invalid payload format\"}", "application/json");
            return;
        }

        int updated = 0;
        for (auto& entry : payload["products"]) {
            int pid = entry.value("id", 0);
            auto pit = products.find(pid);
            if (pit != products.end()) {
                if (entry.contains("stock")) pit->second.stock = entry["stock"].get<int>();
                if (entry.contains("price")) pit->second.price = entry["price"].get<double>();
                updated++;
            }
        }

        json resp = {{"message", "Inventory updated"}, {"updated_count", updated}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get(R"(/api/products/(\d+)/label)", [](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(data_mutex);
        int pid = std::stoi(req.matches[1]);
        auto it = products.find(pid);
        if (it == products.end()) {
            res.status = 404;
            res.set_content("{\"error\":\"Product not found\"}", "application/json");
            return;
        }

        auto& p = it->second;
        std::ostringstream oss;
        oss << p.name << " - $" << std::fixed << std::setprecision(2) << p.price
            << " [" << p.category << "]";

        json resp = {{"label", oss.str()}, {"product_id", pid}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/config/warehouse", [](const httplib::Request&, httplib::Response& res) {
        json resp = {{"location", "us-east-1"}, {"api_endpoint", WAREHOUSE_ENDPOINT},
                     {"max_batch_size", 50}, {"retry_attempts", 3}};
        res.set_content(resp.dump(), "application/json");
    });

    svr.Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"status\":\"healthy\",\"service\":\"inventory-api\"}", "application/json");
    });

    printf("Inventory Service API running on port 9110\n");
    svr.listen("0.0.0.0", 9110);
    return 0;
}
