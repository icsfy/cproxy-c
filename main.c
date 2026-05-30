#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <fcntl.h>

enum Mode { MODE_REDIRECT, MODE_TPROXY, MODE_TRACE };

// Global state for cleanup
volatile sig_atomic_t g_keep_running = 1;
int g_cgroup_created = 0;
int g_is_v2 = 0;
char g_cgroup_path[256] = {0};
char g_output_chain[128] = {0};
char g_prerouting_chain[128] = {0};
enum Mode g_mode = MODE_REDIRECT;
int g_tproxy_mark = 0;
int g_has_override_dns = 0;

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

int is_valid_ip(const char *ip) {
    return is_valid_ipv4(ip) || is_valid_ipv6(ip);
}

int is_valid_bypass_str(const char* str) {
    if (!str || strlen(str) == 0) return 1;
    char* copy = strdup(str);
    if (!copy) return 0;

    int valid = 1;
    char* token = strtok(copy, ",");
    while (token != NULL) {
        while (*token == ' ') token++;
        char* end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (strlen(token) > 0) {
            char part[128];
            strncpy(part, token, sizeof(part) - 1);
            part[sizeof(part) - 1] = '\0';
            char* slash = strchr(part, '/');
            if (slash) {
                *slash = '\0';
                int mask = atoi(slash + 1);
                if (is_valid_ipv4(part)) {
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
        token = strtok(NULL, ",");
    }
    free(copy);
    return valid;
}

int run_cmd_v(const char *fmt, va_list args, int silent) {
    char cmd_buf[1024];
    vsnprintf(cmd_buf, sizeof(cmd_buf), fmt, args);

    pid_t pid = fork();
    if (pid == 0) {
        if (silent) {
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
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            if (!silent) {
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
        if (!silent) perror("fork failed");
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

    char bypass_copy[512];
    strncpy(bypass_copy, bypass_str, sizeof(bypass_copy) - 1);
    bypass_copy[sizeof(bypass_copy) - 1] = '\0';

    int is_ipv6 = (strcmp(iptables_cmd, "ip6tables") == 0);
    char* token = strtok(bypass_copy, ",");
    while (token != NULL) {
        // Trim spaces
        while(*token == ' ') token++;
        char* end = token + strlen(token) - 1;
        while(end > token && *end == ' ') *end-- = '\0';

        if (strlen(token) > 0) {
            char ip_only[128];
            strncpy(ip_only, token, sizeof(ip_only)-1);
            ip_only[sizeof(ip_only)-1] = '\0';
            char* slash = strchr(ip_only, '/');
            if (slash) *slash = '\0';

            int is_this_v4 = is_valid_ipv4(ip_only);
            int is_this_v6 = is_valid_ipv6(ip_only);

            if ((is_ipv6 && is_this_v6) || (!is_ipv6 && is_this_v4)) {
                CHECK(run_cmd("%s -w -t %s -A %s -d %s -j RETURN", iptables_cmd, table, chain, token));
            }
        }
        token = strtok(NULL, ",");
    }
    return 0;
}

void cleanup(void) {
    static int cleaned_up = 0;
    if (cleaned_up) return;
    cleaned_up = 1;

    // Block signals during cleanup to prevent re-entrancy issues
    sigset_t set;
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, NULL);

    if (g_mode == MODE_REDIRECT) {
        if (g_output_chain[0] != '\0') {
            run_cmd_silent("iptables -w -t nat -D OUTPUT -j %s", g_output_chain);
            run_cmd_silent("iptables -w -t nat -F %s", g_output_chain);
            run_cmd_silent("iptables -w -t nat -X %s", g_output_chain);

            run_cmd_silent("ip6tables -w -t raw -D OUTPUT -j %s", g_output_chain);
            run_cmd_silent("ip6tables -w -t raw -F %s", g_output_chain);
            run_cmd_silent("ip6tables -w -t raw -X %s", g_output_chain);
        }
    } else if (g_mode == MODE_TPROXY) {
        if (g_prerouting_chain[0] != '\0') {
            run_cmd_silent("iptables -w -t mangle -D PREROUTING -j %s", g_prerouting_chain);
            run_cmd_silent("iptables -w -t mangle -F %s", g_prerouting_chain);
            run_cmd_silent("iptables -w -t mangle -X %s", g_prerouting_chain);
        }
        if (g_output_chain[0] != '\0') {
            run_cmd_silent("iptables -w -t mangle -D OUTPUT -j %s", g_output_chain);
            run_cmd_silent("iptables -w -t mangle -F %s", g_output_chain);
            run_cmd_silent("iptables -w -t mangle -X %s", g_output_chain);

            run_cmd_silent("ip6tables -w -t raw -D OUTPUT -j %s", g_output_chain);
            run_cmd_silent("ip6tables -w -t raw -F %s", g_output_chain);
            run_cmd_silent("ip6tables -w -t raw -X %s", g_output_chain);
        }
        if (g_has_override_dns && g_output_chain[0] != '\0') {
            run_cmd_silent("iptables -w -t nat -D OUTPUT -j %s", g_output_chain);
            run_cmd_silent("iptables -w -t nat -F %s", g_output_chain);
            run_cmd_silent("iptables -w -t nat -X %s", g_output_chain);
        }
        if (g_tproxy_mark != 0) {
            run_cmd_silent("ip rule delete fwmark %d table %d", g_tproxy_mark, g_tproxy_mark);
            run_cmd_silent("ip route delete local 0.0.0.0/0 dev lo table %d", g_tproxy_mark);
        }
    } else if (g_mode == MODE_TRACE) {
        if (g_output_chain[0] != '\0') {
            run_cmd_silent("iptables -w -t raw -D OUTPUT -j %s", g_output_chain);
            run_cmd_silent("iptables -w -t raw -F %s", g_output_chain);
            run_cmd_silent("iptables -w -t raw -X %s", g_output_chain);

            run_cmd_silent("ip6tables -w -t raw -D OUTPUT -j %s", g_output_chain);
            run_cmd_silent("ip6tables -w -t raw -F %s", g_output_chain);
            run_cmd_silent("ip6tables -w -t raw -X %s", g_output_chain);
        }
    }

    if (g_cgroup_created && g_cgroup_path[0] != '\0') {
        // Move all remaining processes back to the parent cgroup to ensure rmdir succeeds
        char parent_tasks_file[512];
        char cg_base_path[256];
        strncpy(cg_base_path, g_cgroup_path, sizeof(cg_base_path) - 1);
        cg_base_path[sizeof(cg_base_path) - 1] = '\0';
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
                char tasks_file[512];
                snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_cgroup_path);
                FILE *f = fopen(tasks_file, "r");
                if (!f) {
                    snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_cgroup_path);
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
        rmdir(g_cgroup_path);
        g_cgroup_created = 0;
    }
}

void sig_handler(int sig) {
    (void)sig;
    g_keep_running = 0;
}

int setup_cgroup(pid_t pid, const char *cg_base) {
    snprintf(g_cgroup_path, sizeof(g_cgroup_path), "%s/cproxy-%d", cg_base, pid);

    if (mkdir(g_cgroup_path, 0755) != 0) {
        if (errno != EEXIST) {
            perror("Failed to create cgroup directory");
            return -1;
        }
    }
    g_cgroup_created = 1;

    char tasks_file[512];
    snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_cgroup_path);
    FILE *f = fopen(tasks_file, "w");
    if (!f) {
        snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_cgroup_path);
        f = fopen(tasks_file, "w");
        if (!f) {
            perror("Failed to open cgroup.procs or tasks");
            return -1;
        }
    }
    fprintf(f, "%d\n", pid);
    fclose(f);

    if (!g_is_v2) {
        char classid_file[512];
        snprintf(classid_file, sizeof(classid_file), "%s/net_cls.classid", g_cgroup_path);
        f = fopen(classid_file, "w");
        if (f) {
            fprintf(f, "%d\n", pid);
            fclose(f);
        }
    }
    return 0;
}

int setup_iptables_redirect(pid_t pid, int port, int redirect_dns, int is_v2, const char* cgroup_path, const char* bypass_str) {
    snprintf(g_output_chain, sizeof(g_output_chain), "cp_rd_out_%d", pid);

    CHECK(init_chain("nat", g_output_chain, "OUTPUT", "iptables"));
    CHECK(apply_bypass_rules(bypass_str, g_output_chain, "nat", "iptables"));

    CHECK(run_cmd("iptables -w -t nat -A %s -p udp -o lo ! --dport 53 -j RETURN", g_output_chain));
    CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -o lo ! --dport 53 -j RETURN", g_output_chain));

    CHECK(init_chain("raw", g_output_chain, "OUTPUT", "ip6tables"));
    CHECK(apply_bypass_rules(bypass_str, g_output_chain, "raw", "ip6tables"));

    run_cmd_silent("ip6tables -w -t raw -A %s -o lo -j RETURN", g_output_chain);

    if (is_v2) {
        CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --path %s -j REDIRECT --to-ports %d", g_output_chain, cgroup_path, port));
        if (redirect_dns) {
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --path %s --dport 53 -j REDIRECT --to-ports %d", g_output_chain, cgroup_path, port));
        }
        run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -j DROP", g_output_chain, cgroup_path);
    } else {
        CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --cgroup %d -j REDIRECT --to-ports %d", g_output_chain, pid, port));
        if (redirect_dns) {
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --cgroup %d --dport 53 -j REDIRECT --to-ports %d", g_output_chain, pid, port));
        }
        run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup %d -j DROP", g_output_chain, pid);
    }
    return 0;
}

int setup_iptables_tproxy(pid_t pid, int port, const char* override_dns, int is_v2, const char* cgroup_path, const char* bypass_str) {
    g_tproxy_mark = pid;
    snprintf(g_output_chain, sizeof(g_output_chain), "cp_tp_out_%d", pid);
    snprintf(g_prerouting_chain, sizeof(g_prerouting_chain), "cp_tp_pre_%d", pid);

    run_cmd_silent("ip rule delete fwmark %d table %d", g_tproxy_mark, g_tproxy_mark);
    run_cmd_silent("ip route delete local 0.0.0.0/0 dev lo table %d", g_tproxy_mark);

    CHECK(run_cmd("ip rule add fwmark %d table %d", g_tproxy_mark, g_tproxy_mark));
    CHECK(run_cmd("ip route add local 0.0.0.0/0 dev lo table %d", g_tproxy_mark));

    CHECK(init_chain("mangle", g_prerouting_chain, "PREROUTING", "iptables"));
    CHECK(apply_bypass_rules(bypass_str, g_prerouting_chain, "mangle", "iptables"));
    CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -m mark --mark %d -j TPROXY --on-ip 127.0.0.1 --on-port %d", g_prerouting_chain, g_tproxy_mark, port));
    CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -m mark --mark %d -j TPROXY --on-ip 127.0.0.1 --on-port %d", g_prerouting_chain, g_tproxy_mark, port));

    CHECK(init_chain("mangle", g_output_chain, "OUTPUT", "iptables"));
    CHECK(apply_bypass_rules(bypass_str, g_output_chain, "mangle", "iptables"));

    CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -o lo ! --dport 53 -j RETURN", g_output_chain));
    CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -o lo ! --dport 53 -j RETURN", g_output_chain));

    if (override_dns && strlen(override_dns) > 0) {
        g_has_override_dns = 1;
        CHECK(init_chain("nat", g_output_chain, "OUTPUT", "iptables"));
        CHECK(apply_bypass_rules(bypass_str, g_output_chain, "nat", "iptables"));

        CHECK(run_cmd("iptables -w -t nat -A %s -p udp -o lo ! --dport 53 -j RETURN", g_output_chain));
        CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -o lo ! --dport 53 -j RETURN", g_output_chain));
    }

    CHECK(init_chain("raw", g_output_chain, "OUTPUT", "ip6tables"));
    CHECK(apply_bypass_rules(bypass_str, g_output_chain, "raw", "ip6tables"));
    run_cmd_silent("ip6tables -w -t raw -A %s -o lo -j RETURN", g_output_chain);

    if (is_v2) {
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -m cgroup --path %s -j MARK --set-mark %d", g_output_chain, cgroup_path, g_tproxy_mark));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -m cgroup --path %s -j MARK --set-mark %d", g_output_chain, cgroup_path, g_tproxy_mark));
        run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -j DROP", g_output_chain, cgroup_path);
        if (g_has_override_dns) {
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --path %s --dport 53 -j DNAT --to-destination %s", g_output_chain, cgroup_path, override_dns));
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --path %s --dport 53 -j DNAT --to-destination %s", g_output_chain, cgroup_path, override_dns));
        }
    } else {
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -m cgroup --cgroup %d -j MARK --set-mark %d", g_output_chain, pid, g_tproxy_mark));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -m cgroup --cgroup %d -j MARK --set-mark %d", g_output_chain, pid, g_tproxy_mark));
        run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup %d -j DROP", g_output_chain, pid);
        if (g_has_override_dns) {
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --cgroup %d --dport 53 -j DNAT --to-destination %s", g_output_chain, pid, override_dns));
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --cgroup %d --dport 53 -j DNAT --to-destination %s", g_output_chain, pid, override_dns));
        }
    }
    return 0;
}

int setup_iptables_trace(pid_t pid, int is_v2, const char* cgroup_path, const char* bypass_str) {
    snprintf(g_output_chain, sizeof(g_output_chain), "cp_tr_out_%d", pid);

    CHECK(init_chain("raw", g_output_chain, "OUTPUT", "iptables"));
    CHECK(apply_bypass_rules(bypass_str, g_output_chain, "raw", "iptables"));

    CHECK(init_chain("raw", g_output_chain, "OUTPUT", "ip6tables"));
    CHECK(apply_bypass_rules(bypass_str, g_output_chain, "raw", "ip6tables"));

    if (is_v2) {
        CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --path %s -p tcp -j LOG", g_output_chain, cgroup_path));
        CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --path %s -p udp -j LOG", g_output_chain, cgroup_path));
        run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -p tcp -j LOG", g_output_chain, cgroup_path);
        run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -p udp -j LOG", g_output_chain, cgroup_path);
    } else {
        CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --cgroup %d -p tcp -j LOG", g_output_chain, pid));
        CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --cgroup %d -p udp -j LOG", g_output_chain, pid));
        run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup %d -p tcp -j LOG", g_output_chain, pid);
        run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup %d -p udp -j LOG", g_output_chain, pid);
    }
    return 0;
}

int is_cgroup_empty(void) {
    if (!g_cgroup_created || g_cgroup_path[0] == '\0') return 1;
    char tasks_file[512];
    snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_cgroup_path);
    FILE *f = fopen(tasks_file, "r");
    if (!f) {
        snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_cgroup_path);
        f = fopen(tasks_file, "r");
        if (!f) return 1;
    }
    char buf[32];
    int empty = 1;
    if (fgets(buf, sizeof(buf), f) != NULL) {
        empty = 0;
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

    if (check_dependencies() != 0) {
        return 1;
    }

    int port = 1080;
    int redirect_dns = 0;
    char mode_str[32] = "redirect";
    char override_dns[64] = {0};
    char bypass_str[512] = {0};
    pid_t target_pid = 0;
    int status = 0;

    struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"redirect-dns", no_argument, 0, 'd'},
        {"mode", required_argument, 0, 'm'},
        {"override-dns", required_argument, 0, 'o'},
        {"pid", required_argument, 0, 'i'},
        {"bypass", required_argument, 0, 'b'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:dm:o:i:b:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stderr, "Usage: %s [options] -- <command...>\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  -p, --port <port>         Proxy port (default: 1080)\n");
                fprintf(stderr, "  -m, --mode <mode>         Mode: redirect (default), tproxy, trace\n");
                fprintf(stderr, "  -d, --redirect-dns        Redirect DNS in redirect mode\n");
                fprintf(stderr, "  -o, --override-dns <ip>   Override DNS in tproxy mode (IPv4 only)\n");
                fprintf(stderr, "  -b, --bypass <ips>        Comma-separated list of IPs/CIDRs to bypass\n");
                fprintf(stderr, "  -i, --pid <pid>           Attach to an existing process\n");
                fprintf(stderr, "  -h, --help                Show this help message\n");
                return 0;
            case 'p': port = atoi(optarg); break;
            case 'd': redirect_dns = 1; break;
            case 'm': strncpy(mode_str, optarg, sizeof(mode_str)-1); break;
            case 'o':
                if (is_valid_ipv4(optarg)) {
                    strncpy(override_dns, optarg, sizeof(override_dns)-1);
                } else {
                    fprintf(stderr, "Error: Invalid IPv4 address for --override-dns (IPv6 DNS override not yet supported)\n");
                    return 1;
                }
                break;
            case 'i': target_pid = atoi(optarg); break;
            case 'b':
                if (is_valid_bypass_str(optarg)) {
                    strncpy(bypass_str, optarg, sizeof(bypass_str)-1);
                } else {
                    fprintf(stderr, "Error: Invalid characters in --bypass string\n");
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return 1;
        }
    }

    if (strcmp(mode_str, "redirect") == 0) g_mode = MODE_REDIRECT;
    else if (strcmp(mode_str, "tproxy") == 0) g_mode = MODE_TPROXY;
    else if (strcmp(mode_str, "trace") == 0) g_mode = MODE_TRACE;
    else {
        fprintf(stderr, "Unknown mode: %s\n", mode_str);
        return 1;
    }

    if (target_pid == 0 && optind >= argc) {
        fprintf(stderr, "Error: No command specified and no --pid provided.\n");
        return 1;
    }

    if (strlen(bypass_str) == 0) {
        char *env_bypass = getenv("CPROXY_BYPASS");
        if (env_bypass && is_valid_bypass_str(env_bypass)) {
            strncpy(bypass_str, env_bypass, sizeof(bypass_str)-1);
        }
    }

    atexit(cleanup);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    const char *cg_base = "/sys/fs/cgroup/net_cls";
    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0) {
        g_is_v2 = 1;
        cg_base = "/sys/fs/cgroup";
    }

    int pipefd[2];
    pid_t child_pid = 0;
    char *sudo_user = getenv("SUDO_USER");
    char *sudo_uid_str = getenv("SUDO_UID");
    char *sudo_gid_str = getenv("SUDO_GID");

    if (target_pid == 0) {
        if (pipe(pipefd) == -1) {
            perror("pipe failed");
            return 1;
        }

        child_pid = fork();
        if (child_pid < 0) {
            perror("fork failed");
            return 1;
        }

        if (child_pid == 0) {
            close(pipefd[1]);
            char sync_buf;
            if (read(pipefd[0], &sync_buf, 1) <= 0) {
                _exit(1);
            }
            close(pipefd[0]);

            if (sudo_user && sudo_uid_str && sudo_gid_str) {
                uid_t uid = atoi(sudo_uid_str);
                gid_t gid = atoi(sudo_gid_str);

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

                struct passwd *pw = getpwuid(uid);
                if (pw) {
                    setenv("HOME", pw->pw_dir, 1);
                    setenv("USER", pw->pw_name, 1);
                    setenv("LOGNAME", pw->pw_name, 1);
                }
            }

            char env_str[64];
            snprintf(env_str, sizeof(env_str), "cproxy/%d", port);
            setenv("CPROXY_ENV", env_str, 1);

            char **child_argv = &argv[optind];
            execvp(child_argv[0], child_argv);
            perror("execvp failed");
            _exit(1);
        }
        close(pipefd[0]);
    }

    pid_t process_to_proxy = (target_pid > 0) ? target_pid : child_pid;

    if (setup_cgroup(process_to_proxy, cg_base) != 0) {
        if (target_pid == 0) close(pipefd[1]);
        return 1;
    }

    char relative_cg_path[256] = {0};
    if (g_is_v2) {
        snprintf(relative_cg_path, sizeof(relative_cg_path), "cproxy-%d", process_to_proxy);
    }

    int res = 0;
    if (g_mode == MODE_REDIRECT) {
        res = setup_iptables_redirect(process_to_proxy, port, redirect_dns, g_is_v2, relative_cg_path, bypass_str);
    } else if (g_mode == MODE_TPROXY) {
        res = setup_iptables_tproxy(process_to_proxy, port, override_dns, g_is_v2, relative_cg_path, bypass_str);
    } else if (g_mode == MODE_TRACE) {
        res = setup_iptables_trace(process_to_proxy, g_is_v2, relative_cg_path, bypass_str);
    }

    if (res != 0) {
        if (target_pid == 0) close(pipefd[1]);
        return 1;
    }

    if (target_pid > 0) {
        printf("Proxying existing PID %d in mode '%s'. Press Ctrl+C to stop...\n", target_pid, mode_str);
        while (g_keep_running) {
            if (kill(target_pid, 0) == -1 && errno == ESRCH) {
                printf("Target process %d has exited.\n", target_pid);
                break;
            }
            sleep(1);
        }
    } else {
        if (write(pipefd[1], "A", 1) != 1) {
            perror("Failed to synchronize with child");
        }
        close(pipefd[1]);

        while (waitpid(child_pid, &status, 0) == -1) {
            if (errno == EINTR && g_keep_running == 0) {
                kill(child_pid, SIGINT);
            }
        }
    }

    // Wait for all processes in the cgroup to exit (e.g., descendants)
    while (g_keep_running && !is_cgroup_empty()) {
        sleep(1);
    }

    if (target_pid > 0) return 0;

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);

    return 0;
}
