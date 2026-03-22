#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <cstdlib>
#include <cstring>
#include <mutex>

class BankAccount {
public:
    std::string owner;
    long balance;
    std::vector<std::string> log;

    BankAccount(const std::string &name, long initial)
        : owner(name), balance(initial) {}

    void deposit(long amount) {
        long current = balance;
        std::this_thread::yield();
        balance = current + amount;
        log.push_back("deposit:" + std::to_string(amount));
    }

    bool withdraw(long amount) {
        if (balance >= amount) {
            std::this_thread::yield();
            balance -= amount;
            log.push_back("withdraw:" + std::to_string(amount));
            return true;
        }
        return false;
    }

    bool transferTo(BankAccount &other, long amount) {
        if (balance >= amount) {
            std::this_thread::yield();
            balance -= amount;
            other.balance += amount;
            log.push_back("transfer_out:" + std::to_string(amount));
            other.log.push_back("transfer_in:" + std::to_string(amount));
            return true;
        }
        return false;
    }
};

class TicketPool {
public:
    int available;
    std::map<int, std::string> reservations;
    int nextId = 0;

    TicketPool(int total) : available(total) {}

    int reserve(const std::string &customer) {
        if (available > 0) {
            std::this_thread::yield();
            available--;
            nextId++;
            reservations[nextId] = customer;
            return nextId;
        }
        return -1;
    }

    bool cancel(int id) {
        auto it = reservations.find(id);
        if (it != reservations.end()) {
            reservations.erase(it);
            std::this_thread::yield();
            available++;
            return true;
        }
        return false;
    }
};

class SharedCounter {
public:
    long value = 0;

    void increment() {
        long current = value;
        std::this_thread::yield();
        value = current + 1;
    }
};

class Inventory {
public:
    std::map<std::string, int> products;
    int orderCount = 0;

    void addProduct(const std::string &name, int qty) {
        products[name] = qty;
    }

    bool placeOrder(const std::string &name, int qty) {
        auto it = products.find(name);
        if (it != products.end() && it->second >= qty) {
            int stock = it->second;
            std::this_thread::yield();
            products[name] = stock - qty;
            orderCount++;
            return true;
        }
        return false;
    }

    void restock(const std::string &name, int qty) {
        int current = products[name];
        std::this_thread::yield();
        products[name] = current + qty;
    }
};

class LazyConfig {
    static LazyConfig *instance;
    std::map<std::string, std::string> settings;

    LazyConfig() {
        std::this_thread::yield();
        settings["status"] = "initialized";
    }

public:
    static LazyConfig *getInstance() {
        if (instance == nullptr) {
            std::this_thread::yield();
            instance = new LazyConfig();
        }
        return instance;
    }

    void set(const std::string &key, const std::string &val) {
        settings[key] = val;
    }

    std::string get(const std::string &key) {
        auto it = settings.find(key);
        return it != settings.end() ? it->second : "";
    }

    static void reset() {
        delete instance;
        instance = nullptr;
    }
};

LazyConfig *LazyConfig::instance = nullptr;

void runBankSimulation(int numThreads, int iterations) {
    BankAccount alice("Alice", 10000);
    BankAccount bob("Bob", 10000);
    long initialTotal = alice.balance + bob.balance;

    std::vector<std::thread> threads;
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([&alice, &bob, iterations]() {
            for (int i = 0; i < iterations; i++) {
                alice.transferTo(bob, 100);
                bob.transferTo(alice, 100);
            }
        });
    }
    for (auto &th : threads) th.join();

    std::cout << "Bank Simulation (" << numThreads << " threads, "
              << iterations << " iterations)" << std::endl;
    std::cout << "  Initial total: " << initialTotal << std::endl;
    std::cout << "  Final total:   " << alice.balance + bob.balance << std::endl;
    std::cout << "  Alice balance: " << alice.balance << std::endl;
    std::cout << "  Bob balance:   " << bob.balance << std::endl;
}

void runTicketSimulation(int numThreads, int totalTickets) {
    TicketPool pool(totalTickets);
    int successCount = 0, failCount = 0;
    std::mutex resultMu;

    std::vector<std::thread> threads;
    int perThread = totalTickets / numThreads;
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([&pool, &successCount, &failCount, &resultMu, perThread]() {
            for (int i = 0; i < perThread; i++) {
                int rid = pool.reserve("Customer");
                std::lock_guard<std::mutex> lock(resultMu);
                if (rid > 0) successCount++;
                else failCount++;
            }
        });
    }
    for (auto &th : threads) th.join();

    std::cout << "Ticket Simulation (" << numThreads << " threads, "
              << totalTickets << " tickets)" << std::endl;
    std::cout << "  Successful: " << successCount << std::endl;
    std::cout << "  Failed:     " << failCount << std::endl;
    std::cout << "  Remaining:  " << pool.available << std::endl;
}

void runCounterSimulation(int numThreads, int increments) {
    SharedCounter counter;

    std::vector<std::thread> threads;
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([&counter, increments]() {
            for (int i = 0; i < increments; i++) {
                counter.increment();
            }
        });
    }
    for (auto &th : threads) th.join();

    long expected = (long)numThreads * increments;
    std::cout << "Counter Simulation (" << numThreads << " threads, "
              << increments << " increments each)" << std::endl;
    std::cout << "  Expected: " << expected << std::endl;
    std::cout << "  Actual:   " << counter.value << std::endl;
}

void runInventorySimulation(int numThreads, int quantity) {
    Inventory inv;
    inv.addProduct("Widget", quantity);

    std::vector<std::thread> threads;
    int perThread = quantity / numThreads;
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([&inv, perThread]() {
            for (int i = 0; i < perThread; i++) {
                inv.placeOrder("Widget", 1);
            }
        });
    }
    threads.emplace_back([&inv, perThread]() {
        for (int i = 0; i < perThread / 2; i++) {
            inv.restock("Widget", 1);
        }
    });
    for (auto &th : threads) th.join();

    std::cout << "Inventory Simulation (" << numThreads << " threads)" << std::endl;
    std::cout << "  Initial stock: " << quantity << std::endl;
    std::cout << "  Final stock:   " << inv.products["Widget"] << std::endl;
    std::cout << "  Orders:        " << inv.orderCount << std::endl;
}

void runSingletonSimulation(int numThreads) {
    LazyConfig::reset();
    std::vector<int> hashes;
    std::mutex mu;

    std::vector<std::thread> threads;
    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([&hashes, &mu, t]() {
            LazyConfig *cfg = LazyConfig::getInstance();
            cfg->set("worker", "thread-" + std::to_string(t));
            std::lock_guard<std::mutex> lock(mu);
            hashes.push_back(reinterpret_cast<std::intptr_t>(cfg));
        });
    }
    for (auto &th : threads) th.join();

    std::cout << "Singleton Simulation (" << numThreads << " threads)" << std::endl;
    std::cout << "  Instances seen: " << hashes.size() << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <command> [args...]" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  bank <threads> <iterations>     Bank transfer simulation" << std::endl;
        std::cout << "  tickets <threads> <total>        Ticket booking simulation" << std::endl;
        std::cout << "  counter <threads> <increments>   Shared counter simulation" << std::endl;
        std::cout << "  inventory <threads> <quantity>   Inventory simulation" << std::endl;
        std::cout << "  singleton <threads>              Config singleton simulation" << std::endl;
        return 0;
    }

    std::string cmd = argv[1];

    auto getArg = [&](int idx, int def) -> int {
        return idx < argc ? std::atoi(argv[idx]) : def;
    };

    if (cmd == "bank") {
        runBankSimulation(getArg(2, 4), getArg(3, 100));
    } else if (cmd == "tickets") {
        runTicketSimulation(getArg(2, 4), getArg(3, 100));
    } else if (cmd == "counter") {
        runCounterSimulation(getArg(2, 4), getArg(3, 1000));
    } else if (cmd == "inventory") {
        runInventorySimulation(getArg(2, 4), getArg(3, 200));
    } else if (cmd == "singleton") {
        runSingletonSimulation(getArg(2, 8));
    } else {
        std::cerr << "Unknown command: " << cmd << std::endl;
        return 1;
    }

    return 0;
}
