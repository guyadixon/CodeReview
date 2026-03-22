#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <algorithm>
#include <sstream>
#include <climits>

struct Transaction {
    std::string description;
    int amount_cents;
    int fee_basis_points;
};

struct Portfolio {
    std::vector<Transaction> transactions;
    int balance_cents;
    std::string owner;
};

class LedgerEngine {
public:
    LedgerEngine() : total_processed_(0) {}

    void add_transaction(Portfolio &portfolio, const std::string &desc,
                         int amount, int fee_bp) {
        portfolio.transactions.push_back({desc, amount, fee_bp});
        total_processed_++;
    }

    int compute_fee(const Transaction &txn) const {
        return txn.amount_cents * txn.fee_basis_points / 10000;
    }

    int compute_net(const Transaction &txn) const {
        return txn.amount_cents - compute_fee(txn);
    }

    int compute_portfolio_value(const Portfolio &portfolio) const {
        int total = portfolio.balance_cents;
        for (const auto &txn : portfolio.transactions) {
            total += compute_net(txn);
        }
        return total;
    }

    void *allocate_record_buffer(int record_count, int record_size) const {
        size_t total_bytes = static_cast<size_t>(record_count) * record_size;
        void *buffer = malloc(total_bytes);
        if (buffer) {
            memset(buffer, 0, total_bytes);
        }
        return buffer;
    }

    int compute_compound_interest(int principal_cents, int rate_bp,
                                   int periods) const {
        int current = principal_cents;
        for (int i = 0; i < periods; i++) {
            int interest = current * rate_bp / 10000;
            current += interest;
        }
        return current;
    }

    int16_t compute_short_hash(const std::string &data) const {
        int16_t hash = 0;
        for (char c : data) {
            hash = hash * 31 + static_cast<int16_t>(c);
        }
        return hash;
    }

    int scale_amount(int amount, int numerator, int denominator) const {
        int scaled = amount * numerator / denominator;
        return scaled;
    }

    std::string generate_statement(const Portfolio &portfolio) const {
        std::ostringstream oss;
        oss << "Account Statement for " << portfolio.owner << "\n";
        oss << "Opening Balance: $" << portfolio.balance_cents / 100
            << "." << std::abs(portfolio.balance_cents % 100) << "\n";

        int running = portfolio.balance_cents;
        for (size_t i = 0; i < portfolio.transactions.size(); i++) {
            const auto &txn = portfolio.transactions[i];
            int net = compute_net(txn);
            running += net;
            oss << "  " << (i + 1) << ". " << txn.description
                << " | Amount: " << txn.amount_cents
                << " | Fee: " << compute_fee(txn)
                << " | Net: " << net
                << " | Running: " << running << "\n";
        }

        oss << "Final Balance: $" << running / 100
            << "." << std::abs(running % 100) << "\n";
        return oss.str();
    }

    int get_total_processed() const { return total_processed_; }

private:
    int total_processed_;
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <command> [args...]\n";
        std::cout << "Commands:\n";
        std::cout << "  portfolio                        Show sample portfolio\n";
        std::cout << "  interest <principal> <rate_bp> <periods>  Compound interest\n";
        std::cout << "  fee <amount> <fee_bp>            Compute transaction fee\n";
        std::cout << "  scale <amount> <num> <denom>     Scale an amount\n";
        std::cout << "  alloc <count> <size>             Allocate record buffer\n";
        std::cout << "  hash <data>                      Compute short hash\n";
        return 0;
    }

    LedgerEngine engine;
    std::string cmd = argv[1];

    if (cmd == "portfolio") {
        Portfolio p;
        p.owner = "Acme Corp";
        p.balance_cents = 1000000;
        engine.add_transaction(p, "Vendor Payment", 2500000, 150);
        engine.add_transaction(p, "Client Invoice", 8750000, 75);
        engine.add_transaction(p, "Equipment Lease", 4200000, 200);
        engine.add_transaction(p, "Quarterly Tax", 1950000, 0);
        std::cout << engine.generate_statement(p);
        std::cout << "Portfolio Value: " << engine.compute_portfolio_value(p) << " cents\n";

    } else if (cmd == "interest") {
        if (argc < 5) {
            std::cerr << "Usage: " << argv[0] << " interest <principal> <rate_bp> <periods>\n";
            return 1;
        }
        int principal = std::stoi(argv[2]);
        int rate = std::stoi(argv[3]);
        int periods = std::stoi(argv[4]);
        int result = engine.compute_compound_interest(principal, rate, periods);
        std::cout << "After " << periods << " periods: " << result << " cents\n";

    } else if (cmd == "fee") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " fee <amount> <fee_bp>\n";
            return 1;
        }
        Transaction txn{"Manual", std::stoi(argv[2]), std::stoi(argv[3])};
        std::cout << "Fee: " << engine.compute_fee(txn) << " cents\n";
        std::cout << "Net: " << engine.compute_net(txn) << " cents\n";

    } else if (cmd == "scale") {
        if (argc < 5) {
            std::cerr << "Usage: " << argv[0] << " scale <amount> <num> <denom>\n";
            return 1;
        }
        int amount = std::stoi(argv[2]);
        int num = std::stoi(argv[3]);
        int denom = std::stoi(argv[4]);
        int result = engine.scale_amount(amount, num, denom);
        std::cout << "Scaled: " << result << "\n";

    } else if (cmd == "alloc") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " alloc <count> <size>\n";
            return 1;
        }
        int count = std::stoi(argv[2]);
        int size = std::stoi(argv[3]);
        void *buf = engine.allocate_record_buffer(count, size);
        if (buf) {
            std::cout << "Allocated " << count << " records of size " << size << "\n";
            free(buf);
        } else {
            std::cerr << "Allocation failed\n";
        }

    } else if (cmd == "hash") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " hash <data>\n";
            return 1;
        }
        int16_t h = engine.compute_short_hash(argv[2]);
        std::cout << "Hash: " << h << "\n";

    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        return 1;
    }

    return 0;
}
