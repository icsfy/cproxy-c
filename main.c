#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>

#define CPROXY_VERSION "1.2.0"

enum Mode { MODE_REDIRECT, MODE_TPROXY, MODE_TRACE };

typedef struct {
    int port;
    int redirect_dns;
    enum Mode mode;
    char override_dns[64];
    char *bypass_str;
    pid_t target_pid;
    int verbose;
    int is_v2;
    char cg_base[PATH_MAX];
    char cgroup_path[PATH_MAX];
    char output_chain[128];
    char prerouting_chain[128];
    int tproxy_mark;
    int has_override_dns;
    int cgroup_created;
} Context;

// Global context for cleanup and signal handling
static Context g_ctx = {
    .port = 1080,
    .redirect_dns = 0,
    .mode = MODE_REDIRECT,
    .verbose = 0,
    .tproxy_mark = 0,
    .cgroup_created = 0,
    .target_pid = 0
};

volatile sig_atomic_t g_keep_running = 1;

void sig_handler(int sig) {
    (void)sig;
    g_keep_running = 0;
}

double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

int run_cmd_v(const char *fmt, va_list args, int silent) {
    char cmd_buf[4096];
    int n = vsnprintf(cmd_buf, sizeof(cmd_buf), fmt, args);
    if (n < 0 || n >= (int)sizeof(cmd_buf)) {
        if (!silent) fprintf(stderr, "Error: Command too long\n");
        return -1;
    }

    double start = 0;
    if (g_ctx.verbose) {
        printf("[DEBUG] Executing: %s\n", cmd_buf);
        start = get_time_ms();
    }

    pid_t pid = fork();
    if (pid == 0) {
        if (silent && !g_ctx.verbose) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull != -1) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        execl("/bin/sh", "sh", "-c", cmd_buf, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);

        if (g_ctx.verbose) {
            double end = get_time_ms();
            printf("[DEBUG] Command took %.2fms, exit code: %d\n", end - start, WEXITSTATUS(status));
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            if (!silent || g_ctx.verbose) {
                if (WIFEXITED(status)) {
                    fprintf(stderr, "Error: Command returned %d: %s\n", WEXITSTATUS(status), cmd_buf);
                } else {
                    fprintf(stderr, "Error: Command failed: %s\n", cmd_buf);
                }
            }
            return -1;
        }
        return 0;
    } else {
        if (!silent || g_ctx.verbose) perror("fork failed");
        return -1;
    }
}

int run_cmd(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int res = run_cmd_v(fmt, args, 0);
    va_end(args);
    return res;
}

int run_cmd_silent(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int res = run_cmd_v(fmt, args, 1);
    va_end(args);
    return res;
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

#define CHECK(x) do { if ((x) != 0) return -1; } while (0)

int init_chain(const char *table, const char *chain, const char *parent, const char *iptables_cmd) {
    run_cmd_silent("%s -w -t %s -D %s -j %s", iptables_cmd, table, parent, chain);
    run_cmd_silent("%s -w -t %s -F %s", iptables_cmd, table, chain);
    run_cmd_silent("%s -w -t %s -X %s", iptables_cmd, table, chain);

    CHECK(run_cmd("%s -w -t %s -N %s", iptables_cmd, table, chain));
    CHECK(run_cmd("%s -w -t %s -A %s -j %s", iptables_cmd, table, parent, chain));
    return 0;
}

int apply_bypass_rules(const char* bypass_str, const char* chain, const char* table, const char* iptables_cmd) {
    if (!bypass_str || strlen(bypass_str) == 0) return 0;

    char *bypass_copy = strdup(bypass_str);
    if (!bypass_copy) return -1;

    int is_ipv6 = (strcmp(iptables_cmd, "ip6tables") == 0);
    char *saveptr;
    char* token = strtok_r(bypass_copy, ",", &saveptr);
    while (token != NULL) {
        while(*token == ' ') token++;
        char* end = token + strlen(token) - 1;
        while(end > token && *end == ' ') *end-- = '\0';

        if (strlen(token) > 0) {
            char ip_only[512];
            snprintf(ip_only, sizeof(ip_only), "%s", token);
            char* slash = strchr(ip_only, '/');
            if (slash) *slash = '\0';

            int is_this_v4 = is_valid_ipv4(ip_only);
            int is_this_v6 = is_valid_ipv6(ip_only);

            if ((is_ipv6 && is_this_v6) || (!is_ipv6 && is_this_v4)) {
                if (run_cmd("%s -w -t %s -A %s -d %s -j RETURN", iptables_cmd, table, chain, token) != 0) {
                    free(bypass_copy);
                    return -1;
                }
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(bypass_copy);
    return 0;
}

void cleanup(void) {
    static int cleaned_up = 0;
    if (cleaned_up) return;
    cleaned_up = 1;

    sigset_t set;
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, NULL);

    int pid = (int)g_ctx.target_pid;

    if (pid > 0) {
        if (g_ctx.mode == MODE_REDIRECT) {
            char out4_chain[128], out6_chain[128];
            snprintf(out4_chain, sizeof(out4_chain), "CP_RD_OUT_%d", pid);
            snprintf(out6_chain, sizeof(out6_chain), "CP6_RD_OUT_%d", pid);

            run_cmd_silent("iptables -w -t nat -D OUTPUT -j %s", out4_chain);
            run_cmd_silent("iptables -w -t nat -F %s", out4_chain);
            run_cmd_silent("iptables -w -t nat -X %s", out4_chain);

            run_cmd_silent("ip6tables -w -t raw -D OUTPUT -j %s", out6_chain);
            run_cmd_silent("ip6tables -w -t raw -F %s", out6_chain);
            run_cmd_silent("ip6tables -w -t raw -X %s", out6_chain);
        } else if (g_ctx.mode == MODE_TPROXY) {
            char out4_chain[128], pre4_chain[128], out6_chain[128], dns4_chain[128];
            snprintf(out4_chain, sizeof(out4_chain), "CP_TP_OUT_%d", pid);
            snprintf(pre4_chain, sizeof(pre4_chain), "CP_TP_PRE_%d", pid);
            snprintf(out6_chain, sizeof(out6_chain), "CP6_TP_OUT_%d", pid);
            snprintf(dns4_chain, sizeof(dns4_chain), "CP_TP_DNS_%d", pid);

            run_cmd_silent("iptables -w -t mangle -D PREROUTING -j %s", pre4_chain);
            run_cmd_silent("iptables -w -t mangle -F %s", pre4_chain);
            run_cmd_silent("iptables -w -t mangle -X %s", pre4_chain);

            run_cmd_silent("iptables -w -t mangle -D OUTPUT -j %s", out4_chain);
            run_cmd_silent("iptables -w -t mangle -F %s", out4_chain);
            run_cmd_silent("iptables -w -t mangle -X %s", out4_chain);

            run_cmd_silent("ip6tables -w -t raw -D OUTPUT -j %s", out6_chain);
            run_cmd_silent("ip6tables -w -t raw -F %s", out6_chain);
            run_cmd_silent("ip6tables -w -t raw -X %s", out6_chain);

            if (g_ctx.has_override_dns) {
                run_cmd_silent("iptables -w -t nat -D OUTPUT -j %s", dns4_chain);
                run_cmd_silent("iptables -w -t nat -F %s", dns4_chain);
                run_cmd_silent("iptables -w -t nat -X %s", dns4_chain);
            }

            if (g_ctx.tproxy_mark != 0) {
                run_cmd_silent("ip rule delete fwmark %d table %d", g_ctx.tproxy_mark, g_ctx.tproxy_mark);
                run_cmd_silent("ip route delete local 0.0.0.0/0 dev lo table %d", g_ctx.tproxy_mark);
            }
        } else if (g_ctx.mode == MODE_TRACE) {
            char out4_chain[128], out6_chain[128];
            snprintf(out4_chain, sizeof(out4_chain), "CP_TR_OUT_%d", pid);
            snprintf(out6_chain, sizeof(out6_chain), "CP6_TR_OUT_%d", pid);

            run_cmd_silent("iptables -w -t raw -D OUTPUT -j %s", out4_chain);
            run_cmd_silent("iptables -w -t raw -F %s", out4_chain);
            run_cmd_silent("iptables -w -t raw -X %s", out4_chain);

            run_cmd_silent("ip6tables -w -t raw -D OUTPUT -j %s", out6_chain);
            run_cmd_silent("ip6tables -w -t raw -F %s", out6_chain);
            run_cmd_silent("ip6tables -w -t raw -X %s", out6_chain);
        }
    }

    if (g_ctx.cgroup_created && g_ctx.cgroup_path[0] != '\0') {
        char parent_tasks_file[PATH_MAX + 64];
        char cg_base_path[PATH_MAX];
        snprintf(cg_base_path, sizeof(cg_base_path), "%s", g_ctx.cgroup_path);
        char *last_slash = strrchr(cg_base_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(parent_tasks_file, sizeof(parent_tasks_file), "%s/cgroup.procs", cg_base_path);
            FILE *f_parent = fopen(parent_tasks_file, "w");
            if (!f_parent) {
                snprintf(parent_tasks_file, sizeof(parent_tasks_file), "%s/tasks", cg_base_path);
                f_parent = fopen(parent_tasks_file, "w");
            }
            if (f_parent) {
                char tasks_file[PATH_MAX + 64];
                snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_ctx.cgroup_path);
                FILE *f = fopen(tasks_file, "r");
                if (!f) {
                    snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_ctx.cgroup_path);
                    f = fopen(tasks_file, "r");
                }
                if (f) {
                    char buf[32];
                    while (fgets(buf, sizeof(buf), f) != NULL) {
                        int pid = atoi(buf);
                        if (pid > 0) {
                            fprintf(f_parent, "%d\n", pid);
                            fflush(f_parent);
                        }
                    }
                    fclose(f);
                }
                fclose(f_parent);
            }
        }
        if (rmdir(g_ctx.cgroup_path) != 0 && errno != ENOENT) {
            if (g_ctx.verbose) perror("rmdir cgroup failed");
        }
        g_ctx.cgroup_created = 0;
    }

    if (g_ctx.bypass_str) {
        free(g_ctx.bypass_str);
        g_ctx.bypass_str = NULL;
    }
}

int setup_cgroup(pid_t pid) {
    if (snprintf(g_ctx.cgroup_path, sizeof(g_ctx.cgroup_path), "%s/cproxy-%d", g_ctx.cg_base, pid) >= (int)sizeof(g_ctx.cgroup_path)) {
        fprintf(stderr, "Error: Cgroup path too long\n");
        return -1;
    }

    if (mkdir(g_ctx.cgroup_path, 0755) != 0) {
        if (errno != EEXIST) {
            perror("Failed to create cgroup directory");
            return -1;
        }
    }
    g_ctx.cgroup_created = 1;

    char tasks_file[PATH_MAX + 64];
    snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_ctx.cgroup_path);
    FILE *f = fopen(tasks_file, "w");
    if (!f) {
        snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_ctx.cgroup_path);
        f = fopen(tasks_file, "w");
        if (!f) {
            perror("Failed to open cgroup.procs or tasks");
            return -1;
        }
    }
    fprintf(f, "%d\n", pid);
    fclose(f);

    if (!g_ctx.is_v2) {
        char classid_file[PATH_MAX + 64];
        snprintf(classid_file, sizeof(classid_file), "%s/net_cls.classid", g_ctx.cgroup_path);
        f = fopen(classid_file, "w");
        if (f) {
            // net_cls.classid expects a hex value like 0xAAAABBBB (major:minor)
            // We use (1 << 16) | (pid & 0xFFFF) to ensure a unique-ish classid
            fprintf(f, "0x%08x\n", (1 << 16) | (pid & 0xFFFF));
            fclose(f);
        }
    }
    return 0;
}

int setup_iptables(pid_t pid) {
    char relative_cg_path[PATH_MAX] = {0};
    if (g_ctx.is_v2) {
        snprintf(relative_cg_path, sizeof(relative_cg_path), "/cproxy-%d", pid);
    }

    if (g_ctx.mode == MODE_REDIRECT) {
        snprintf(g_ctx.output_chain, sizeof(g_ctx.output_chain), "CP_RD_OUT_%d", pid);
        CHECK(init_chain("nat", g_ctx.output_chain, "OUTPUT", "iptables"));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, g_ctx.output_chain, "nat", "iptables"));
        CHECK(run_cmd("iptables -w -t nat -A %s -p udp -o lo ! --dport 53 -j RETURN", g_ctx.output_chain));
        CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -o lo ! --dport 53 -j RETURN", g_ctx.output_chain));

        char out6_chain[128];
        snprintf(out6_chain, sizeof(out6_chain), "CP6_RD_OUT_%d", pid);
        CHECK(init_chain("raw", out6_chain, "OUTPUT", "ip6tables"));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, out6_chain, "raw", "ip6tables"));
        run_cmd_silent("ip6tables -w -t raw -A %s -o lo -j RETURN", out6_chain);

        if (g_ctx.is_v2) {
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --path %s -j REDIRECT --to-ports %d", g_ctx.output_chain, relative_cg_path, g_ctx.port));
            if (g_ctx.redirect_dns) {
                CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --path %s --dport 53 -j REDIRECT --to-ports %d", g_ctx.output_chain, relative_cg_path, g_ctx.port));
            }
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -j DROP", out6_chain, relative_cg_path);
        } else {
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --cgroup 0x%08x -j REDIRECT --to-ports %d", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.port));
            if (g_ctx.redirect_dns) {
                CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --cgroup 0x%08x --dport 53 -j REDIRECT --to-ports %d", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.port));
            }
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup 0x%08x -j DROP", out6_chain, (1 << 16) | (pid & 0xFFFF));
        }
    } else if (g_ctx.mode == MODE_TPROXY) {
        g_ctx.tproxy_mark = pid;
        snprintf(g_ctx.output_chain, sizeof(g_ctx.output_chain), "CP_TP_OUT_%d", pid);
        snprintf(g_ctx.prerouting_chain, sizeof(g_ctx.prerouting_chain), "CP_TP_PRE_%d", pid);

        run_cmd_silent("ip rule delete fwmark %d table %d", g_ctx.tproxy_mark, g_ctx.tproxy_mark);
        run_cmd_silent("ip route delete local 0.0.0.0/0 dev lo table %d", g_ctx.tproxy_mark);

        CHECK(run_cmd("ip rule add fwmark %d table %d", g_ctx.tproxy_mark, g_ctx.tproxy_mark));
        CHECK(run_cmd("ip route add local 0.0.0.0/0 dev lo table %d", g_ctx.tproxy_mark));

        CHECK(init_chain("mangle", g_ctx.prerouting_chain, "PREROUTING", "iptables"));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, g_ctx.prerouting_chain, "mangle", "iptables"));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -m mark --mark %d -j TPROXY --on-ip 127.0.0.1 --on-port %d", g_ctx.prerouting_chain, g_ctx.tproxy_mark, g_ctx.port));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -m mark --mark %d -j TPROXY --on-ip 127.0.0.1 --on-port %d", g_ctx.prerouting_chain, g_ctx.tproxy_mark, g_ctx.port));

        CHECK(init_chain("mangle", g_ctx.output_chain, "OUTPUT", "iptables"));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, g_ctx.output_chain, "mangle", "iptables"));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -o lo ! --dport 53 -j RETURN", g_ctx.output_chain));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -o lo ! --dport 53 -j RETURN", g_ctx.output_chain));

        char dns_chain[128] = {0};
        if (g_ctx.override_dns[0] != '\0') {
            g_ctx.has_override_dns = 1;
            snprintf(dns_chain, sizeof(dns_chain), "CP_TP_DNS_%d", pid);
            CHECK(init_chain("nat", dns_chain, "OUTPUT", "iptables"));
            CHECK(apply_bypass_rules(g_ctx.bypass_str, dns_chain, "nat", "iptables"));
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp -o lo ! --dport 53 -j RETURN", dns_chain));
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -o lo ! --dport 53 -j RETURN", dns_chain));
        }

        char out6_chain[128];
        snprintf(out6_chain, sizeof(out6_chain), "CP6_TP_OUT_%d", pid);
        CHECK(init_chain("raw", out6_chain, "OUTPUT", "ip6tables"));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, out6_chain, "raw", "ip6tables"));
        run_cmd_silent("ip6tables -w -t raw -A %s -o lo -j RETURN", out6_chain);

        if (g_ctx.is_v2) {
            CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -m cgroup --path %s -j MARK --set-mark %d", g_ctx.output_chain, relative_cg_path, g_ctx.tproxy_mark));
            CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -m cgroup --path %s -j MARK --set-mark %d", g_ctx.output_chain, relative_cg_path, g_ctx.tproxy_mark));
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -j DROP", out6_chain, relative_cg_path);
            if (g_ctx.has_override_dns) {
                CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --path %s --dport 53 -j DNAT --to-destination %s", dns_chain, relative_cg_path, g_ctx.override_dns));
                CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --path %s --dport 53 -j DNAT --to-destination %s", dns_chain, relative_cg_path, g_ctx.override_dns));
            }
        } else {
            CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -m cgroup --cgroup 0x%08x -j MARK --set-mark %d", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.tproxy_mark));
            CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -m cgroup --cgroup 0x%08x -j MARK --set-mark %d", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.tproxy_mark));
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup 0x%08x -j DROP", out6_chain, (1 << 16) | (pid & 0xFFFF));
            if (g_ctx.has_override_dns) {
                CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --cgroup 0x%08x --dport 53 -j DNAT --to-destination %s", dns_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.override_dns));
                CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --cgroup 0x%08x --dport 53 -j DNAT --to-destination %s", dns_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.override_dns));
            }
        }
    } else if (g_ctx.mode == MODE_TRACE) {
        snprintf(g_ctx.output_chain, sizeof(g_ctx.output_chain), "CP_TR_OUT_%d", pid);
        CHECK(init_chain("raw", g_ctx.output_chain, "OUTPUT", "iptables"));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, g_ctx.output_chain, "raw", "iptables"));

        char out6_chain[128];
        snprintf(out6_chain, sizeof(out6_chain), "CP6_TR_OUT_%d", pid);
        CHECK(init_chain("raw", out6_chain, "OUTPUT", "ip6tables"));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, out6_chain, "raw", "ip6tables"));

        if (g_ctx.is_v2) {
            CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --path %s -p tcp -j LOG --log-prefix \"cproxy: \"", g_ctx.output_chain, relative_cg_path));
            CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --path %s -p udp -j LOG --log-prefix \"cproxy: \"", g_ctx.output_chain, relative_cg_path));
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -p tcp -j LOG --log-prefix \"cproxy: \"", out6_chain, relative_cg_path);
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -p udp -j LOG --log-prefix \"cproxy: \"", out6_chain, relative_cg_path);
        } else {
            CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --cgroup 0x%08x -p tcp -j LOG --log-prefix \"cproxy: \"", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF)));
            CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --cgroup 0x%08x -p udp -j LOG --log-prefix \"cproxy: \"", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF)));
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup 0x%08x -p tcp -j LOG --log-prefix \"cproxy: \"", out6_chain, (1 << 16) | (pid & 0xFFFF));
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup 0x%08x -p udp -j LOG --log-prefix \"cproxy: \"", out6_chain, (1 << 16) | (pid & 0xFFFF));
        }
    }
    return 0;
}

int is_cgroup_empty(void) {
    if (!g_ctx.cgroup_created || g_ctx.cgroup_path[0] == '\0') return 1;
    char tasks_file[PATH_MAX + 64];
    snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_ctx.cgroup_path);
    FILE *f = fopen(tasks_file, "r");
    if (!f) {
        snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_ctx.cgroup_path);
        f = fopen(tasks_file, "r");
        if (!f) return 1;
    }
    char buf[32];
    int empty = 1;
    while (fgets(buf, sizeof(buf), f) != NULL) {
        if (atoi(buf) > 0) {
            empty = 0;
            break;
        }
    }
    fclose(f);
    return empty;
}

int run_cmd_status(const char *fmt, ...) {
    char cmd_buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd_buf, sizeof(cmd_buf), fmt, args);
    va_end(args);

    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull != -1) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl("/bin/sh", "sh", "-c", cmd_buf, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    return -1;
}

int check_dependencies(void) {
    const char *deps[] = {"iptables", "ip", "ip6tables"};
    for (size_t i = 0; i < sizeof(deps) / sizeof(deps[0]); i++) {
        if (run_cmd_status("which %s", deps[i]) != 0) {
            fprintf(stderr, "Error: '%s' command not found. Please install it.\n", deps[i]);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "Error: cproxy must be run as root (use sudo)\n");
        return 1;
    }

    if (check_dependencies() != 0) return 1;

    atexit(cleanup);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    char mode_str[32] = "redirect";
    pid_t target_pid = 0;
    int status = 0;

    struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"redirect-dns", no_argument, 0, 'd'},
        {"mode", required_argument, 0, 'm'},
        {"override-dns", required_argument, 0, 'o'},
        {"pid", required_argument, 0, 'i'},
        {"bypass", required_argument, 0, 'b'},
        {"verbose", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    int ret = 0;
    while ((opt = getopt_long(argc, argv, "p:dm:o:i:b:Vhv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v': printf("cproxy version %s\n", CPROXY_VERSION); return 0;
            case 'h':
                fprintf(stderr, "Usage: %s [options] -- <command...>\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  -p, --port <port>         Proxy port (default: 1080)\n");
                fprintf(stderr, "  -m, --mode <mode>         Mode: redirect (default), tproxy, trace\n");
                fprintf(stderr, "  -d, --redirect-dns        Redirect DNS in redirect mode\n");
                fprintf(stderr, "  -o, --override-dns <ip>   Override DNS in tproxy mode (IPv4 only)\n");
                fprintf(stderr, "  -b, --bypass <ips>        Comma-separated list of IPs/CIDRs to bypass\n");
                fprintf(stderr, "  -i, --pid <pid>           Attach to an existing process\n");
                fprintf(stderr, "  -V, --verbose             Show detailed debug information\n");
                fprintf(stderr, "  -h, --help                Show this help message\n");
                return 0;
            case 'p': g_ctx.port = atoi(optarg); break;
            case 'd': g_ctx.redirect_dns = 1; break;
            case 'm': snprintf(mode_str, sizeof(mode_str), "%s", optarg); break;
            case 'V': g_ctx.verbose = 1; break;
            case 'o':
                if (is_valid_ipv4(optarg)) {
                    snprintf(g_ctx.override_dns, sizeof(g_ctx.override_dns), "%s", optarg);
                } else {
                    fprintf(stderr, "Error: Invalid IPv4 address for --override-dns\n");
                    ret = 1; goto cleanup_all;
                }
                break;
            case 'i': target_pid = atoi(optarg); break;
            case 'b':
                if (is_valid_bypass_str(optarg)) {
                    if (g_ctx.bypass_str) {
                        size_t old_len = strlen(g_ctx.bypass_str);
                        size_t add_len = strlen(optarg);
                        char *new_str = malloc(old_len + add_len + 2); // +1 for comma, +1 for null
                        if (!new_str) {
                            perror("malloc failed");
                            ret = 1; goto cleanup_all;
                        }
                        memcpy(new_str, g_ctx.bypass_str, old_len);
                        new_str[old_len] = ',';
                        memcpy(new_str + old_len + 1, optarg, add_len);
                        new_str[old_len + 1 + add_len] = '\0';
                        free(g_ctx.bypass_str);
                        g_ctx.bypass_str = new_str;
                    } else {
                        g_ctx.bypass_str = strdup(optarg);
                        if (!g_ctx.bypass_str) {
                            perror("strdup failed");
                            ret = 1; goto cleanup_all;
                        }
                    }
                } else {
                    fprintf(stderr, "Error: Invalid --bypass string\n");
                    ret = 1; goto cleanup_all;
                }
                break;
            default: return 1;
        }
    }

    if (strcmp(mode_str, "redirect") == 0) g_ctx.mode = MODE_REDIRECT;
    else if (strcmp(mode_str, "tproxy") == 0) g_ctx.mode = MODE_TPROXY;
    else if (strcmp(mode_str, "trace") == 0) g_ctx.mode = MODE_TRACE;
    else { fprintf(stderr, "Unknown mode: %s\n", mode_str); ret = 1; goto cleanup_all; }

    if (target_pid == 0 && optind >= argc) {
        fprintf(stderr, "Error: No command specified and no --pid provided.\n");
        ret = 1; goto cleanup_all;
    }

    if (!g_ctx.bypass_str) {
        char *env_bypass = getenv("CPROXY_BYPASS");
        if (env_bypass && is_valid_bypass_str(env_bypass)) g_ctx.bypass_str = strdup(env_bypass);
    }

    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0) {
        g_ctx.is_v2 = 1;
        snprintf(g_ctx.cg_base, sizeof(g_ctx.cg_base), "/sys/fs/cgroup");
    } else {
        snprintf(g_ctx.cg_base, sizeof(g_ctx.cg_base), "/sys/fs/cgroup/net_cls");
        if (stat(g_ctx.cg_base, &st) != 0) {
            fprintf(stderr, "Error: Cgroup v1 net_cls controller not found at %s\n", g_ctx.cg_base);
            ret = 1; goto cleanup_all;
        }
    }

    if (g_ctx.verbose) printf("[INFO] Detected Cgroup v%d mode\n", g_ctx.is_v2 ? 2 : 1);

    int pipefd[2];
    pid_t child_pid = 0;
    if (target_pid == 0) {
        if (pipe(pipefd) == -1) { perror("pipe failed"); ret = 1; goto cleanup_all; }
        child_pid = fork();
        if (child_pid < 0) { perror("fork failed"); ret = 1; goto cleanup_all; }
        if (child_pid == 0) {
            close(pipefd[1]);
            char sync_buf;
            if (read(pipefd[0], &sync_buf, 1) <= 0) _exit(1);
            close(pipefd[0]);

            char *sudo_user = getenv("SUDO_USER");
            char *sudo_uid_str = getenv("SUDO_UID");
            char *sudo_gid_str = getenv("SUDO_GID");
            if (sudo_user && sudo_uid_str && sudo_gid_str) {
                uid_t uid = (uid_t)atoi(sudo_uid_str);
                gid_t gid = (gid_t)atoi(sudo_gid_str);

                // Get password entry while still root
                struct passwd *pw = getpwuid(uid);

                if (initgroups(sudo_user, gid) != 0) {
                    perror("initgroups failed");
                    _exit(1);
                }
                if (setgid(gid) != 0) {
                    perror("setgid failed");
                    _exit(1);
                }
                if (setuid(uid) != 0) {
                    perror("setuid failed");
                    _exit(1);
                }

                if (pw) {
                    setenv("HOME", pw->pw_dir, 1);
                    setenv("USER", pw->pw_name, 1);
                    setenv("LOGNAME", pw->pw_name, 1);
                }
            }
            char env_str[64];
            snprintf(env_str, sizeof(env_str), "cproxy/%d", g_ctx.port);
            setenv("CPROXY_ENV", env_str, 1);
            execvp(argv[optind], &argv[optind]);
            perror("execvp failed"); _exit(1);
        }
        close(pipefd[0]);
    }

    pid_t process_to_proxy = (target_pid > 0) ? target_pid : child_pid;
    g_ctx.target_pid = process_to_proxy;

    if (setup_cgroup(process_to_proxy) != 0) {
        if (target_pid == 0) close(pipefd[1]);
        ret = 1; goto cleanup_all;
    }
    if (setup_iptables(process_to_proxy) != 0) {
        if (target_pid == 0) close(pipefd[1]);
        ret = 1; goto cleanup_all;
    }

    if (target_pid > 0) {
        printf("Proxying PID %d. Press Ctrl+C to stop...\n", target_pid);
        while (g_keep_running) {
            if (kill(target_pid, 0) == -1 && errno == ESRCH) break;
            usleep(100000);
        }
    } else {
        if (write(pipefd[1], "A", 1) != 1) perror("Sync failed");
        close(pipefd[1]);
        while (g_keep_running) {
            int r = waitpid(child_pid, &status, WNOHANG);
            if (r == child_pid) break;
            else if (r == -1 && errno != EINTR) break;
            usleep(100000);
        }
        if (!g_keep_running && kill(child_pid, 0) == 0) {
            kill(child_pid, SIGTERM);
            waitpid(child_pid, &status, 0);
        }
    }

    int wait_timeout = 50; // 5s
    while (!is_cgroup_empty() && wait_timeout-- > 0) usleep(100000);

    if (target_pid == 0) {
        ret = WIFEXITED(status) ? WEXITSTATUS(status) : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 0);
    }

cleanup_all:
    return ret;
}
