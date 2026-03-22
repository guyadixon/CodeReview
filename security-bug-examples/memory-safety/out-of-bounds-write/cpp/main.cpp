#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <sstream>
#include <ctime>

struct Measurement {
    int sensor_id;
    char label[48];
    double reading;
    uint32_t timestamp;
};

class SensorLog {
public:
    static constexpr int MAX_ENTRIES = 128;

    SensorLog() : count_(0) {
        entries_ = new Measurement[MAX_ENTRIES];
        std::memset(entries_, 0, MAX_ENTRIES * sizeof(Measurement));
    }

    ~SensorLog() {
        delete[] entries_;
    }

    void set_label(int index, const char *label) {
        std::strcpy(entries_[index].label, label);
    }

    int add_entry(int sensor_id, const char *label, double reading, uint32_t ts) {
        if (count_ >= MAX_ENTRIES) return -1;
        Measurement *m = &entries_[count_];
        m->sensor_id = sensor_id;
        set_label(count_, label);
        m->reading = reading;
        m->timestamp = ts;
        count_++;
        return count_ - 1;
    }

    void print_all() const {
        std::cout << "Sensor Log (" << count_ << " entries):" << std::endl;
        for (int i = 0; i < count_; i++) {
            std::cout << "  [" << entries_[i].sensor_id << "] "
                      << entries_[i].label << " = "
                      << entries_[i].reading << " @ "
                      << entries_[i].timestamp << std::endl;
        }
    }

    Measurement *get(int index) { return &entries_[index]; }
    int count() const { return count_; }

private:
    Measurement *entries_;
    int count_;
};

class DataPipeline {
public:
    DataPipeline(int capacity) {
        capacity_ = capacity;
        buffer_ = new double[capacity_];
        size_ = 0;
    }

    ~DataPipeline() {
        delete[] buffer_;
    }

    void ingest(const double *data, int count) {
        for (int i = 0; i < count; i++) {
            buffer_[size_ + i] = data[i];
        }
        size_ += count;
    }

    void normalize() {
        if (size_ == 0) return;
        double max_val = buffer_[0];
        for (int i = 1; i < size_; i++) {
            if (buffer_[i] > max_val) max_val = buffer_[i];
        }
        if (max_val != 0.0) {
            for (int i = 0; i < size_; i++) {
                buffer_[i] /= max_val;
            }
        }
    }

    void print() const {
        std::cout << "Pipeline (" << size_ << "/" << capacity_ << "):" << std::endl;
        for (int i = 0; i < size_; i++) {
            std::cout << "  [" << i << "] " << buffer_[i] << std::endl;
        }
    }

    int size() const { return size_; }
    int capacity() const { return capacity_; }

private:
    double *buffer_;
    int capacity_;
    int size_;
};

static char *build_report(const SensorLog &log) {
    uint32_t num_entries = static_cast<uint32_t>(log.count());
    uint32_t line_size = 80;
    uint32_t total = num_entries * line_size;

    char *report = new char[total];
    std::memset(report, 0, total);

    int offset = 0;
    for (int i = 0; i < log.count(); i++) {
        offset += std::snprintf(report + offset, total - offset,
                                "Sensor %d: reading logged\n",
                                i + 1);
    }
    return report;
}

static void process_tagged_input(const char *input) {
    char tag[16];
    char payload[256];

    const char *sep = std::strchr(input, ':');
    if (!sep) return;

    size_t tag_len = sep - input;
    std::memcpy(tag, input, tag_len);
    tag[tag_len] = '\0';

    std::strcpy(payload, sep + 1);

    std::cout << "Tag: " << tag << std::endl;
    std::cout << "Payload: " << payload << std::endl;
}

static void aggregate_readings(const char *csv) {
    double readings[32];
    int count = 0;

    std::string input(csv);
    std::istringstream stream(input);
    std::string token;

    while (std::getline(stream, token, ',')) {
        readings[count] = std::stod(token);
        count++;
    }

    double sum = 0;
    for (int i = 0; i < count; i++) {
        sum += readings[i];
    }
    std::cout << "Aggregate: " << sum << " (from " << count << " readings)" << std::endl;
}

static void copy_with_prefix(char *dest, size_t dest_size,
                              const char *prefix, const char *src) {
    size_t prefix_len = std::strlen(prefix);
    size_t src_len = std::strlen(src);
    size_t needed = prefix_len + src_len + 2;

    char *temp = new char[needed];
    std::memcpy(temp, prefix, prefix_len);
    temp[prefix_len] = '_';
    std::memcpy(temp + prefix_len + 1, src, src_len + 1);

    std::memcpy(dest, temp, needed);
    delete[] temp;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <command> [args...]" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  log <sensor_id> <label> <reading>  Add sensor reading" << std::endl;
        std::cout << "  report                             Generate report" << std::endl;
        std::cout << "  pipeline <v1,v2,...>                Process data pipeline" << std::endl;
        std::cout << "  tagged <tag:payload>                Process tagged input" << std::endl;
        std::cout << "  aggregate <v1,v2,...>               Aggregate readings" << std::endl;
        std::cout << "  prefix <prefix> <text>              Add prefix to text" << std::endl;
        return 0;
    }

    std::string cmd(argv[1]);
    SensorLog log;

    if (cmd == "log" && argc >= 5) {
        int sid = std::atoi(argv[2]);
        double reading = std::atof(argv[4]);
        uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
        int idx = log.add_entry(sid, argv[3], reading, ts);
        if (idx >= 0) {
            std::cout << "Logged entry " << idx << std::endl;
        }
        log.print_all();
    } else if (cmd == "report") {
        log.add_entry(1, "temp_sensor_a", 23.5, 1000);
        log.add_entry(2, "pressure_gauge_b", 101.3, 1001);
        log.add_entry(3, "humidity_monitor_c", 65.2, 1002);
        char *report = build_report(log);
        std::cout << report;
        delete[] report;
    } else if (cmd == "pipeline" && argc >= 3) {
        std::string csv(argv[2]);
        std::vector<double> values;
        std::istringstream stream(csv);
        std::string token;
        while (std::getline(stream, token, ',')) {
            values.push_back(std::stod(token));
        }

        DataPipeline pipeline(8);
        pipeline.ingest(values.data(), static_cast<int>(values.size()));
        pipeline.normalize();
        pipeline.print();
    } else if (cmd == "tagged" && argc >= 3) {
        process_tagged_input(argv[2]);
    } else if (cmd == "aggregate" && argc >= 3) {
        aggregate_readings(argv[2]);
    } else if (cmd == "prefix" && argc >= 4) {
        char result[64];
        copy_with_prefix(result, sizeof(result), argv[2], argv[3]);
        std::cout << "Result: " << result << std::endl;
    } else {
        std::cerr << "Unknown command: " << cmd << std::endl;
        return 1;
    }

    return 0;
}
