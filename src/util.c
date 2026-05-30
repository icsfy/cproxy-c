#include "cproxy.h"

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, "[INFO] ");
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void log_debug(const char *fmt, ...) {
    if (!g_ctx.verbose && !g_ctx.dry_run) return;
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, "[DEBUG] ");
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
}

double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

int is_valid_ipv4(const char *ip) {
    if (!ip) return 0;
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

int is_valid_ipv6(const char *ip) {
    if (!ip) return 0;
    struct in6_addr addr;
    return inet_pton(AF_INET6, ip, &addr) == 1;
}

int is_valid_bypass_str(const char* str) {
    if (!str || strlen(str) == 0) return 1;
    char* copy = strdup(str);
    if (!copy) return 0;

    int valid = 1;
    char* saveptr;
    char* token = strtok_r(copy, ",", &saveptr);
    while (token != NULL) {
        while (*token == ' ') token++;
        size_t len = strlen(token);
        while (len > 0 && token[len-1] == ' ') {
            token[len-1] = '\0';
            len--;
        }

        if (len > 0) {
            char part[512];
            if (len >= sizeof(part)) {
                valid = 0;
                break;
            }
            snprintf(part, sizeof(part), "%s", token);
            char* slash = strchr(part, '/');
            if (slash) {
                *slash = '\0';
                char *endptr;
                long mask = strtol(slash + 1, &endptr, 10);
                if (*(slash + 1) == '\0' || *endptr != '\0') {
                    valid = 0;
                } else if (is_valid_ipv4(part)) {
                    if (mask < 0 || mask > 32) valid = 0;
                } else if (is_valid_ipv6(part)) {
                    if (mask < 0 || mask > 128) valid = 0;
                } else {
                    valid = 0;
                }
            } else {
                if (!is_valid_ipv4(part) && !is_valid_ipv6(part)) {
                    valid = 0;
                }
            }
        }
        if (!valid) break;
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    return valid;
}

int check_dependencies(void) {
    const char *deps[] = {"iptables", "ip", "ip6tables"};
    for (size_t i = 0; i < sizeof(deps) / sizeof(deps[0]); i++) {
        if (run_cmd_silent("command -v %s", deps[i]) != 0) {
            fprintf(stderr, "Error: '%s' command not found. Please install it.\n", deps[i]);
            return -1;
        }
    }
    return 0;
}
