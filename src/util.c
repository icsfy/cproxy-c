#include "cproxy.h"

void log_msg(LogLevel level, const char *fmt, ...) {
    if (level == LOG_LEVEL_DEBUG && !g_ctx.verbose && !g_ctx.dry_run) return;

    FILE *out = (level == LOG_LEVEL_ERROR || level == LOG_LEVEL_WARN) ? stderr : stdout;
    const char *prefix = "";
    switch (level) {
        case LOG_LEVEL_DEBUG: prefix = "[DEBUG] "; break;
        case LOG_LEVEL_INFO:  prefix = "[INFO]  "; break;
        case LOG_LEVEL_WARN:  prefix = "[WARN]  "; break;
        case LOG_LEVEL_ERROR: prefix = "[ERROR] "; break;
    }

    fprintf(out, "%s", prefix);
    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
    fprintf(out, "\n");
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

int is_pid_alive(pid_t pid) {
    if (pid <= 0) return 0;
    return kill(pid, 0) == 0 || errno != ESRCH;
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

int parse_bypass_rules(Context *ctx) {
    if (!ctx->bypass_str || strlen(ctx->bypass_str) == 0) return 0;

    char *copy = strdup(ctx->bypass_str);
    if (!copy) return -1;

    // Count tokens first
    int count = 0;
    char *saveptr;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token) {
        count++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);

    if (count == 0) return 0;

    ctx->bypass_rules = calloc(count, sizeof(BypassRule));
    if (!ctx->bypass_rules) return -1;

    copy = strdup(ctx->bypass_str);
    token = strtok_r(copy, ",", &saveptr);
    int idx = 0;
    while (token) {
        while (*token == ' ') token++;
        size_t len = strlen(token);
        while (len > 0 && token[len-1] == ' ') {
            token[len-1] = '\0';
            len--;
        }

        if (len > 0) {
            snprintf(ctx->bypass_rules[idx].addr, sizeof(ctx->bypass_rules[idx].addr), "%s", token);

            char ip_only[64];
            snprintf(ip_only, sizeof(ip_only), "%s", token);
            char *slash = strchr(ip_only, '/');
            if (slash) *slash = '\0';

            if (is_valid_ipv6(ip_only)) {
                ctx->bypass_rules[idx].is_v6 = true;
            } else {
                ctx->bypass_rules[idx].is_v6 = false;
            }
            idx++;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    ctx->bypass_count = idx;
    free(copy);
    return 0;
}

int is_command_available(const char *cmd) {
    char *path = getenv("PATH");
    if (!path) path = "/usr/sbin:/usr/bin:/sbin:/bin";
    char *path_copy = strdup(path);
    if (!path_copy) return 0;

    char *saveptr;
    char *dir = strtok_r(path_copy, ":", &saveptr);
    char full_path[PATH_MAX];
    while (dir) {
        snprintf(full_path, sizeof(full_path), "%s/%s", dir, cmd);
        if (access(full_path, X_OK) == 0) {
            free(path_copy);
            return 1;
        }
        dir = strtok_r(NULL, ":", &saveptr);
    }
    free(path_copy);
    return 0;
}

int check_dependencies(void) {
    const char *deps[] = {"iptables", "ip"};
    for (size_t i = 0; i < sizeof(deps) / sizeof(deps[0]); i++) {
        if (!is_command_available(deps[i])) {
            log_error("'%s' command not found. Please install it.", deps[i]);
            return -1;
        }
    }

    if (!is_command_available("ip6tables")) {
        log_warn("'ip6tables' not found. IPv6 support will be disabled.");
    }

    return 0;
}
