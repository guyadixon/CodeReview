#include <iostream>
#include <string>
#include <sstream>
#include <array>
#include <memory>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <map>
#include <unistd.h>

const std::string LOG_DIR = "/var/log/sysadmin";

std::string exec_command(const std::string &cmd) {
    std::array<char, 4096> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        return "Failed to execute command";
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

void print_usage(const std::string &prog) {
    std::cout << "Network & System Administration Toolkit\n"
              << "Usage: " << prog << " <command> [options]\n\n"
              << "Commands:\n"
              << "  ping <host>                     Ping a remote host\n"
              << "  dns <domain> [type]             DNS lookup\n"
              << "  logs <keyword> [file] [lines]   Search log files\n"
              << "  diskinfo [path]                 Show disk usage\n"
              << "  archive <path> [name]           Create tar archive\n"
              << "  netcheck <host> <port>          Check port connectivity\n"
              << "  sysinfo                         Show system information\n"
              << "  whois <domain>                  WHOIS lookup\n"
              << "  traceroute <host>               Trace route to host\n"
              << "  interactive                     Interactive diagnostics\n";
}

void ping_host(const std::string &host) {
    std::string cmd = "ping -c 3 " + host;
    std::cout << "Pinging " << host << "...\n";
    std::cout << exec_command(cmd) << std::endl;
}

void dns_lookup(const std::string &domain, std::string record_type) {
    std::vector<std::string> valid_types = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"};
    if (std::find(valid_types.begin(), valid_types.end(), record_type) == valid_types.end()) {
        record_type = "A";
    }

    std::string cmd = "dig " + record_type + " " + domain + " +short";
    std::cout << "Looking up " << record_type << " record for " << domain << "...\n";
    std::cout << exec_command(cmd) << std::endl;
}

void search_logs(const std::string &keyword, const std::string &logfile, const std::string &lines) {
    std::string log_path = LOG_DIR + "/" + logfile;

    if (access(log_path.c_str(), R_OK) != 0) {
        std::cerr << "Log file not accessible: " << log_path << std::endl;
        return;
    }

    std::string cmd = "tail -n " + lines + " " + log_path + " | grep '" + keyword + "'";
    std::cout << "Searching for '" << keyword << "' in " << logfile
              << " (last " << lines << " lines)...\n";
    std::string result = exec_command(cmd);
    if (result.empty()) {
        std::cout << "No matches found.\n";
    } else {
        std::cout << result;
    }
}

void disk_info(const std::string &path) {
    std::string cmd = "df -h " + path;
    std::cout << "Disk usage for " << path << ":\n";
    std::cout << exec_command(cmd) << std::endl;
}

std::string sanitize_name(const std::string &name) {
    std::string safe = name;
    std::replace(safe.begin(), safe.end(), '/', '_');
    std::replace(safe.begin(), safe.end(), '\\', '_');
    return safe;
}

void archive_path(const std::string &filepath, const std::string &name) {
    std::string safe_name = sanitize_name(name);
    std::string archive = "/tmp/" + safe_name + ".tar.gz";
    std::string cmd = "tar czf " + archive + " " + filepath;
    std::cout << "Creating archive " << archive << "...\n";
    std::string result = exec_command(cmd);
    if (!result.empty()) {
        std::cout << result;
    }
    std::cout << "Archive created: " << archive << std::endl;
}

void check_port(const std::string &host, const std::string &port) {
    int port_num = std::stoi(port);
    if (port_num < 1 || port_num > 65535) {
        std::cerr << "Invalid port number: " << port << std::endl;
        return;
    }
    std::string cmd = "nc -zv -w 3 " + host + " " + port;
    std::cout << "Checking " << host << ":" << port << "...\n";
    std::string result = exec_command(cmd);
    std::cout << result << std::endl;
}

void system_info() {
    std::cout << "=== System Information ===\n\n";

    std::cout << "Hostname: " << exec_command("hostname");
    std::cout << "Kernel: " << exec_command("uname -r");
    std::cout << "Uptime: " << exec_command("uptime -p");
    std::cout << "\nDisk Usage:\n" << exec_command("df -h /");
    std::cout << "\nMemory:\n" << exec_command("free -h");
}

void whois_lookup(const std::string &domain) {
    std::string cmd = "whois " + domain;
    std::cout << "WHOIS lookup for " << domain << "...\n";
    std::string output = exec_command(cmd);

    std::istringstream stream(output);
    std::string line;
    std::cout << "\nKey Information:\n";
    while (std::getline(stream, line)) {
        if (line.find("Domain Name:") != std::string::npos ||
            line.find("Registrar:") != std::string::npos ||
            line.find("Creation Date:") != std::string::npos ||
            line.find("Registry Expiry Date:") != std::string::npos) {
            std::cout << "  " << line << "\n";
        }
    }
}

void traceroute_host(const std::string &host) {
    std::string cmd = "traceroute -m 15 " + host;
    std::cout << "Tracing route to " << host << "...\n";
    std::cout << exec_command(cmd) << std::endl;
}

void interactive_mode() {
    std::string input;
    std::cout << "Entering interactive diagnostics mode.\n"
              << "Type 'quit' to exit.\n\n";

    while (true) {
        std::cout << "diag> ";
        std::cout.flush();

        if (!std::getline(std::cin, input)) {
            break;
        }

        if (input == "quit" || input == "exit") {
            break;
        }

        if (input.empty()) {
            continue;
        }

        std::cout << exec_command(input) << std::endl;
    }
    std::cout << "Exiting interactive mode.\n";
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "ping") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " ping <host>\n";
            return 1;
        }
        ping_host(argv[2]);
    } else if (command == "dns") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " dns <domain> [type]\n";
            return 1;
        }
        std::string rtype = (argc >= 4) ? argv[3] : "A";
        dns_lookup(argv[2], rtype);
    } else if (command == "logs") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " logs <keyword> [file] [lines]\n";
            return 1;
        }
        std::string logfile = (argc >= 4) ? argv[3] : "syslog";
        std::string lines = (argc >= 5) ? argv[4] : "100";
        search_logs(argv[2], logfile, lines);
    } else if (command == "diskinfo") {
        std::string path = (argc >= 3) ? argv[2] : "/";
        disk_info(path);
    } else if (command == "archive") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " archive <path> [name]\n";
            return 1;
        }
        std::string name = (argc >= 4) ? argv[3] : "archive";
        archive_path(argv[2], name);
    } else if (command == "netcheck") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " netcheck <host> <port>\n";
            return 1;
        }
        check_port(argv[2], argv[3]);
    } else if (command == "sysinfo") {
        system_info();
    } else if (command == "whois") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " whois <domain>\n";
            return 1;
        }
        whois_lookup(argv[2]);
    } else if (command == "traceroute") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " traceroute <host>\n";
            return 1;
        }
        traceroute_host(argv[2]);
    } else if (command == "interactive") {
        interactive_mode();
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
