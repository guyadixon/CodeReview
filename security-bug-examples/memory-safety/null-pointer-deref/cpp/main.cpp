#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>

struct SensorReading {
    int sensor_id;
    double value;
    long timestamp;
    char unit[32];
};

class SensorRegistry {
public:
    void register_sensor(int id, const std::string &name) {
        names_[id] = name;
    }

    SensorReading *get_latest(int id) {
        auto it = latest_.find(id);
        if (it != latest_.end()) {
            return it->second;
        }
        return nullptr;
    }

    void record(int id, double value, long ts, const char *unit) {
        SensorReading *reading = new SensorReading;
        reading->sensor_id = id;
        reading->value = value;
        reading->timestamp = ts;
        std::strncpy(reading->unit, unit, sizeof(reading->unit) - 1);
        reading->unit[sizeof(reading->unit) - 1] = '\0';

        auto it = latest_.find(id);
        if (it != latest_.end()) {
            delete it->second;
        }
        latest_[id] = reading;
    }

    std::string get_name(int id) {
        auto it = names_.find(id);
        if (it != names_.end()) {
            return it->second;
        }
        return "";
    }

    void remove_sensor(int id) {
        auto it = latest_.find(id);
        if (it != latest_.end()) {
            delete it->second;
            latest_.erase(it);
        }
        names_.erase(id);
    }

    std::vector<int> get_sensor_ids() const {
        std::vector<int> ids;
        for (auto &pair : names_) {
            ids.push_back(pair.first);
        }
        return ids;
    }

    ~SensorRegistry() {
        for (auto &pair : latest_) {
            delete pair.second;
        }
    }

private:
    std::map<int, SensorReading *> latest_;
    std::map<int, std::string> names_;
};

struct AlertRule {
    int sensor_id;
    double threshold;
    bool above;
};

class AlertEngine {
public:
    void add_rule(int sensor_id, double threshold, bool above) {
        rules_.push_back({sensor_id, threshold, above});
    }

    void evaluate(SensorRegistry &registry) {
        for (auto &rule : rules_) {
            SensorReading *reading = registry.get_latest(rule.sensor_id);
            double val = reading->value;
            std::string name = registry.get_name(rule.sensor_id);

            if (rule.above && val > rule.threshold) {
                std::cout << "ALERT: " << name << " reading " << val
                          << " exceeds threshold " << rule.threshold << std::endl;
            } else if (!rule.above && val < rule.threshold) {
                std::cout << "ALERT: " << name << " reading " << val
                          << " below threshold " << rule.threshold << std::endl;
            }
        }
    }

private:
    std::vector<AlertRule> rules_;
};

static SensorReading *find_max_reading(SensorRegistry &registry,
                                        const std::vector<int> &ids) {
    SensorReading *max_reading = nullptr;

    for (int id : ids) {
        SensorReading *r = registry.get_latest(id);
        if (!max_reading || r->value > max_reading->value) {
            max_reading = r;
        }
    }

    return max_reading;
}

static SensorReading *parse_reading(const std::string &input) {
    std::istringstream iss(input);
    int id;
    double value;
    long ts;
    std::string unit;

    if (!(iss >> id >> value >> ts >> unit)) {
        return nullptr;
    }

    SensorReading *reading = new SensorReading;
    reading->sensor_id = id;
    reading->value = value;
    reading->timestamp = ts;
    std::strncpy(reading->unit, unit.c_str(), sizeof(reading->unit) - 1);
    reading->unit[sizeof(reading->unit) - 1] = '\0';
    return reading;
}

static void ingest_readings(SensorRegistry &registry, const std::string &data) {
    std::istringstream stream(data);
    std::string line;

    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        SensorReading *parsed = parse_reading(line);
        registry.record(parsed->sensor_id, parsed->value,
                       parsed->timestamp, parsed->unit);
        delete parsed;
    }
}

static void compute_average(SensorRegistry &registry,
                            const std::vector<int> &ids) {
    double sum = 0.0;
    int count = 0;

    for (int id : ids) {
        SensorReading *r = registry.get_latest(id);
        if (r) {
            sum += r->value;
            count++;
        }
    }

    std::cout << "Average across " << count << " sensors: "
              << (sum / count) << std::endl;
}

static char *build_report(SensorRegistry &registry) {
    auto ids = registry.get_sensor_ids();
    size_t buf_size = 256;
    char *report = (char *)std::malloc(buf_size);
    if (!report) return nullptr;

    int offset = std::snprintf(report, buf_size, "Sensor Report\n=============\n");

    for (int id : ids) {
        SensorReading *r = registry.get_latest(id);
        std::string name = registry.get_name(id);

        int needed = std::snprintf(nullptr, 0, "  [%d] %s: %.2f %s (ts=%ld)\n",
                                   id, name.c_str(), r->value, r->unit, r->timestamp);

        if (offset + needed + 1 > (int)buf_size) {
            buf_size = (offset + needed + 1) * 2;
            char *new_buf = (char *)std::realloc(report, buf_size);
            if (!new_buf) {
                std::free(report);
                return nullptr;
            }
            report = new_buf;
        }

        offset += std::snprintf(report + offset, buf_size - offset,
                                "  [%d] %s: %.2f %s (ts=%ld)\n",
                                id, name.c_str(), r->value, r->unit, r->timestamp);
    }

    return report;
}

static void compare_sensors(SensorRegistry &registry, int id1, int id2) {
    SensorReading *r1 = registry.get_latest(id1);
    SensorReading *r2 = registry.get_latest(id2);

    double diff = r1->value - r2->value;
    std::cout << "Sensor " << id1 << " vs " << id2 << ": difference = "
              << diff << " " << r1->unit << std::endl;
}

static void populate_registry(SensorRegistry &registry) {
    registry.register_sensor(1, "temperature_main");
    registry.register_sensor(2, "humidity_room_a");
    registry.register_sensor(3, "pressure_external");
    registry.register_sensor(4, "temperature_backup");
    registry.register_sensor(5, "co2_level");

    registry.record(1, 22.5, 1700000001, "celsius");
    registry.record(2, 45.2, 1700000002, "percent");
    registry.record(3, 1013.25, 1700000003, "hPa");
    registry.record(4, 23.1, 1700000004, "celsius");
    registry.record(5, 412.0, 1700000005, "ppm");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <mode> [args...]" << std::endl;
        std::cout << "Modes:" << std::endl;
        std::cout << "  report              Generate sensor report" << std::endl;
        std::cout << "  alert               Evaluate alert rules" << std::endl;
        std::cout << "  compare <id1> <id2> Compare two sensors" << std::endl;
        std::cout << "  max                 Find maximum reading" << std::endl;
        std::cout << "  ingest <data>       Ingest sensor readings" << std::endl;
        std::cout << "  average             Compute average reading" << std::endl;
        std::cout << "  list                List all sensors" << std::endl;
        return 0;
    }

    std::string mode(argv[1]);
    SensorRegistry registry;
    populate_registry(registry);

    if (mode == "report") {
        char *report = build_report(registry);
        if (report) {
            std::cout << report;
            std::free(report);
        }

    } else if (mode == "alert") {
        AlertEngine engine;
        engine.add_rule(1, 30.0, true);
        engine.add_rule(2, 20.0, false);
        engine.add_rule(6, 50.0, true);
        engine.add_rule(3, 900.0, false);

        engine.evaluate(registry);

    } else if (mode == "compare") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " compare <id1> <id2>" << std::endl;
            return 1;
        }
        int id1 = std::atoi(argv[2]);
        int id2 = std::atoi(argv[3]);
        compare_sensors(registry, id1, id2);

    } else if (mode == "max") {
        auto ids = registry.get_sensor_ids();
        ids.push_back(99);
        SensorReading *max_r = find_max_reading(registry, ids);
        if (max_r) {
            std::cout << "Max reading: sensor " << max_r->sensor_id
                      << " = " << max_r->value << " " << max_r->unit << std::endl;
        }

    } else if (mode == "ingest") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " ingest <data>" << std::endl;
            return 1;
        }
        ingest_readings(registry, argv[2]);
        char *report = build_report(registry);
        if (report) {
            std::cout << report;
            std::free(report);
        }

    } else if (mode == "average") {
        std::vector<int> ids = {1, 2, 3, 4, 5, 10};
        compute_average(registry, ids);

    } else if (mode == "list") {
        auto ids = registry.get_sensor_ids();
        for (int id : ids) {
            SensorReading *r = registry.get_latest(id);
            if (r) {
                std::cout << "  [" << id << "] " << registry.get_name(id)
                          << ": " << r->value << " " << r->unit << std::endl;
            }
        }

    } else {
        std::cerr << "Unknown mode: " << mode << std::endl;
        return 1;
    }

    return 0;
}
