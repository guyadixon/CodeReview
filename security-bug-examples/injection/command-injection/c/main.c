#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CMD 1024
#define MAX_INPUT 256
#define LOG_DIR "/var/log/sysadmin"

void print_usage(const char *prog) {
    printf("System Administration Toolkit\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  ping <host>                    Ping a remote host\n");
    printf("  dns <domain> [type]            DNS lookup\n");
    printf("  logs <keyword> [file] [lines]  Search log files\n");
    printf("  diskinfo [path]                Show disk usage\n");
    printf("  archive <path> [name]          Create tar archive\n");
    printf("  netcheck <host> <port>         Check port connectivity\n");
    printf("  sysinfo                        Show system information\n");
}

void ping_host(const char *host) {
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd), "ping -c 3 %s", host);
    printf("Pinging %s...\n", host);
    system(cmd);
}

void dns_lookup(const char *domain, const char *record_type) {
    char cmd[MAX_CMD];
    const char *valid_types[] = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"};
    int valid = 0;
    for (int i = 0; i < 7; i++) {
        if (strcmp(record_type, valid_types[i]) == 0) {
            valid = 1;
            break;
        }
    }
    if (!valid) {
        record_type = "A";
    }

    snprintf(cmd, sizeof(cmd), "dig %s %s +short", record_type, domain);
    printf("Looking up %s record for %s...\n", record_type, domain);
    system(cmd);
}

void search_logs(const char *keyword, const char *logfile, const char *lines) {
    char cmd[MAX_CMD];
    char log_path[512];

    snprintf(log_path, sizeof(log_path), "%s/%s", LOG_DIR, logfile);

    if (access(log_path, R_OK) != 0) {
        printf("Log file not accessible: %s\n", log_path);
        return;
    }

    snprintf(cmd, sizeof(cmd), "tail -n %s %s | grep '%s'", lines, log_path, keyword);
    printf("Searching for '%s' in %s (last %s lines)...\n", keyword, logfile, lines);
    system(cmd);
}

void disk_info(const char *path) {
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd), "df -h %s", path);
    printf("Disk usage for %s:\n", path);
    system(cmd);
}

char *sanitize_archive_name(const char *name) {
    static char safe_name[MAX_INPUT];
    int j = 0;
    for (int i = 0; name[i] && j < MAX_INPUT - 1; i++) {
        if (name[i] == '/' || name[i] == '\\') {
            safe_name[j++] = '_';
        } else {
            safe_name[j++] = name[i];
        }
    }
    safe_name[j] = '\0';
    return safe_name;
}

void archive_path(const char *filepath, const char *name) {
    char cmd[MAX_CMD];
    char *safe_name = sanitize_archive_name(name);
    snprintf(cmd, sizeof(cmd), "tar czf /tmp/%s.tar.gz %s", safe_name, filepath);
    printf("Creating archive /tmp/%s.tar.gz...\n", safe_name);
    system(cmd);
}

void check_port(const char *host, const char *port) {
    char cmd[MAX_CMD];
    int port_num = atoi(port);
    if (port_num < 1 || port_num > 65535) {
        printf("Invalid port number: %s\n", port);
        return;
    }
    snprintf(cmd, sizeof(cmd), "nc -zv -w 3 %s %s", host, port);
    printf("Checking %s:%s...\n", host, port);
    system(cmd);
}

void system_info(void) {
    printf("=== System Information ===\n\n");

    printf("Hostname: ");
    fflush(stdout);
    system("hostname");

    printf("Kernel: ");
    fflush(stdout);
    system("uname -r");

    printf("\nUptime: ");
    fflush(stdout);
    system("uptime -p");

    printf("\nDisk Usage:\n");
    system("df -h /");

    printf("\nMemory:\n");
    system("free -h");
}

void interactive_mode(void) {
    char input[MAX_INPUT];
    char cmd[MAX_CMD];

    printf("Entering interactive diagnostics mode.\n");
    printf("Type 'quit' to exit.\n\n");

    while (1) {
        printf("diag> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
            break;
        }

        if (strlen(input) == 0) {
            continue;
        }

        snprintf(cmd, sizeof(cmd), "%s", input);
        system(cmd);
    }
    printf("Exiting interactive mode.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "ping") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s ping <host>\n", argv[0]);
            return 1;
        }
        ping_host(argv[2]);
    } else if (strcmp(command, "dns") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s dns <domain> [type]\n", argv[0]);
            return 1;
        }
        const char *rtype = (argc >= 4) ? argv[3] : "A";
        dns_lookup(argv[2], rtype);
    } else if (strcmp(command, "logs") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s logs <keyword> [file] [lines]\n", argv[0]);
            return 1;
        }
        const char *logfile = (argc >= 4) ? argv[3] : "syslog";
        const char *lines = (argc >= 5) ? argv[4] : "100";
        search_logs(argv[2], logfile, lines);
    } else if (strcmp(command, "diskinfo") == 0) {
        const char *path = (argc >= 3) ? argv[2] : "/";
        disk_info(path);
    } else if (strcmp(command, "archive") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s archive <path> [name]\n", argv[0]);
            return 1;
        }
        const char *name = (argc >= 4) ? argv[3] : "archive";
        archive_path(argv[2], name);
    } else if (strcmp(command, "netcheck") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s netcheck <host> <port>\n", argv[0]);
            return 1;
        }
        check_port(argv[2], argv[3]);
    } else if (strcmp(command, "sysinfo") == 0) {
        system_info();
    } else if (strcmp(command, "interactive") == 0) {
        interactive_mode();
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
