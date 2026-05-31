#include "cproxy.h"

#define CHECK(x) do { if ((x) != 0) return -1; } while (0)

static void get_chain_name(char *buf, size_t len, const char *prefix, pid_t pid, bool ipv6) {
    snprintf(buf, len, "CP%s_%s_%d", ipv6 ? "6" : "", prefix, pid);
}

static int has_ip6tables(void) {
    static int cache = -1;
    if (cache == -1) {
        cache = (run_cmd_silent("command -v ip6tables") == 0);
    }
    return cache;
}

static int setup_tproxy_routing(int mark, int family) {
    const char *ip_cmd = (family == AF_INET6) ? "ip -6" : "ip";
    const char *any_addr = (family == AF_INET6) ? "::/0" : "0.0.0.0/0";

    log_debug("Setting up TProxy routing for %s (mark: 0x%x)",
              (family == AF_INET6) ? "IPv6" : "IPv4", mark);

    run_cmd_silent("%s rule delete fwmark 0x%x table %d", ip_cmd, mark, mark);
    run_cmd_silent("%s route delete local %s dev lo table %d", ip_cmd, any_addr, mark);

    CHECK(run_cmd("%s rule add fwmark 0x%x table %d", ip_cmd, mark, mark));
    CHECK(run_cmd("%s route add local %s dev lo table %d", ip_cmd, any_addr, mark));
    return 0;
}

static void cleanup_tproxy_routing(int mark, int family) {
    const char *ip_cmd = (family == AF_INET6) ? "ip -6" : "ip";
    if (mark == 0) return;
    run_cmd_silent("%s rule delete fwmark 0x%x table %d", ip_cmd, mark, mark);
    run_cmd_silent("%s route flush table %d", ip_cmd, mark);
}

int init_chain(const char *table, const char *chain, const char *parent, const char *iptables_cmd, const char *match) {
    run_cmd_silent("%s -w -t %s -D %s %s -j %s", iptables_cmd, table, parent, match ? match : "", chain);
    run_cmd_silent("%s -w -t %s -F %s", iptables_cmd, table, chain);
    run_cmd_silent("%s -w -t %s -X %s", iptables_cmd, table, chain);

    CHECK(run_cmd("%s -w -t %s -N %s", iptables_cmd, table, chain));
    CHECK(run_cmd("%s -w -t %s -A %s %s -j %s", iptables_cmd, table, parent, match ? match : "", chain));
    return 0;
}

static void destroy_chain(const char *table, const char *chain, const char *parent, const char *iptables_cmd, const char *match) {
    run_cmd_silent("%s -w -t %s -D %s %s -j %s", iptables_cmd, table, parent, match ? match : "", chain);
    run_cmd_silent("%s -w -t %s -F %s", iptables_cmd, table, chain);
    run_cmd_silent("%s -w -t %s -X %s", iptables_cmd, table, chain);
}

int apply_bypass_rules(const char* chain, const char* table, const char* iptables_cmd) {
    if (g_ctx.bypass_count == 0) return 0;

    int is_ipv6 = (strcmp(iptables_cmd, "ip6tables") == 0);
    for (int i = 0; i < g_ctx.bypass_count; i++) {
        if (g_ctx.bypass_rules[i].is_v6 == is_ipv6) {
            CHECK(run_cmd("%s -w -t %s -A %s -d %s -j RETURN", iptables_cmd, table, chain, g_ctx.bypass_rules[i].addr));
        }
    }
    return 0;
}

static void get_cgroup_match(char *buf, size_t len, pid_t pid) {
    if (g_ctx.is_v2) {
        // Find the cgroup path relative to /sys/fs/cgroup
        const char *p = strstr(g_ctx.cgroup_path, "/sys/fs/cgroup");
        if (p) {
            p += strlen("/sys/fs/cgroup");
            if (*p == '\0') p = "/";
            snprintf(buf, len, "-m cgroup --path %s", p);
        } else {
            snprintf(buf, len, "-m cgroup --path /cproxy-%d", pid);
        }
    } else {
        unsigned int classid = (((unsigned int)(pid >> 16) + 1) << 16) | (pid & 0xFFFF);
        snprintf(buf, len, "-m cgroup --cgroup 0x%08x", classid);
    }
}

static int setup_redirect(pid_t pid, const char *cg_match) {
    char out4[128], out6[128];
    get_chain_name(out4, sizeof(out4), "RD_OUT", pid, false);

    CHECK(init_chain("nat", out4, "OUTPUT", "iptables", cg_match));
    CHECK(apply_bypass_rules(out4, "nat", "iptables"));

    CHECK(run_cmd("iptables -w -t nat -A %s -p udp -o lo ! --dport 53 -j RETURN", out4));
    CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -o lo ! --dport 53 -j RETURN", out4));

    if (!g_ctx.redirect_dns) {
        CHECK(run_cmd("iptables -w -t nat -A %s -p udp --dport 53 -j RETURN", out4));
        CHECK(run_cmd("iptables -w -t nat -A %s -p tcp --dport 53 -j RETURN", out4));
    }

    if (g_ctx.redirect_dns) {
        CHECK(run_cmd("iptables -w -t nat -A %s -p udp --dport 53 -j REDIRECT --to-ports %d", out4, g_ctx.dns_port));
        CHECK(run_cmd("iptables -w -t nat -A %s -p tcp --dport 53 -j REDIRECT --to-ports %d", out4, g_ctx.dns_port));
    }
    CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -j REDIRECT --to-ports %d", out4, g_ctx.port));

    if (has_ip6tables()) {
        get_chain_name(out6, sizeof(out6), "RD_OUT", pid, true);
        CHECK(init_chain("raw", out6, "OUTPUT", "ip6tables", cg_match));
        CHECK(apply_bypass_rules(out6, "raw", "ip6tables"));
        CHECK(run_cmd("ip6tables -w -t raw -A %s -o lo -j RETURN", out6));
        CHECK(run_cmd("ip6tables -w -t raw -A %s -j DROP", out6));
    }
    return 0;
}

static int setup_tproxy(pid_t pid, const char *cg_match, const char *mark_match) {
    g_ctx.tproxy_mark = pid + 10000;
    char pre4[128], out4[128], pre6[128], out6[128];
    get_chain_name(pre4, sizeof(pre4), "TP_PRE", pid, false);
    get_chain_name(out4, sizeof(out4), "TP_OUT", pid, false);

    CHECK(setup_tproxy_routing(g_ctx.tproxy_mark, AF_INET));

    CHECK(init_chain("mangle", pre4, "PREROUTING", "iptables", mark_match));
    CHECK(apply_bypass_rules(pre4, "mangle", "iptables"));
    if (g_ctx.dns_port != g_ctx.port) {
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp --dport 53 -j TPROXY --on-ip 127.0.0.1 --on-port %d", pre4, g_ctx.dns_port));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp --dport 53 -j TPROXY --on-ip 127.0.0.1 --on-port %d", pre4, g_ctx.dns_port));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp ! --dport 53 -j TPROXY --on-ip 127.0.0.1 --on-port %d", pre4, g_ctx.port));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp ! --dport 53 -j TPROXY --on-ip 127.0.0.1 --on-port %d", pre4, g_ctx.port));
    } else {
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -j TPROXY --on-ip 127.0.0.1 --on-port %d", pre4, g_ctx.port));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port %d", pre4, g_ctx.port));
    }

    CHECK(init_chain("mangle", out4, "OUTPUT", "iptables", cg_match));
    CHECK(apply_bypass_rules(out4, "mangle", "iptables"));
    CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -o lo ! --dport 53 -j RETURN", out4));
    CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -o lo ! --dport 53 -j RETURN", out4));
    CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -j MARK --set-mark 0x%x", out4, g_ctx.tproxy_mark));
    CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -j MARK --set-mark 0x%x", out4, g_ctx.tproxy_mark));

    if (has_ip6tables()) {
        get_chain_name(pre6, sizeof(pre6), "TP_PRE", pid, true);
        get_chain_name(out6, sizeof(out6), "TP_OUT", pid, true);
        CHECK(setup_tproxy_routing(g_ctx.tproxy_mark, AF_INET6));

        CHECK(init_chain("mangle", pre6, "PREROUTING", "ip6tables", mark_match));
        CHECK(apply_bypass_rules(pre6, "mangle", "ip6tables"));
        if (g_ctx.dns_port != g_ctx.port) {
            CHECK(run_cmd("ip6tables -w -t mangle -A %s -p udp --dport 53 -j TPROXY --on-ip ::1 --on-port %d", pre6, g_ctx.dns_port));
            CHECK(run_cmd("ip6tables -w -t mangle -A %s -p tcp --dport 53 -j TPROXY --on-ip ::1 --on-port %d", pre6, g_ctx.dns_port));
            CHECK(run_cmd("ip6tables -w -t mangle -A %s -p udp ! --dport 53 -j TPROXY --on-ip ::1 --on-port %d", pre6, g_ctx.port));
            CHECK(run_cmd("ip6tables -w -t mangle -A %s -p tcp ! --dport 53 -j TPROXY --on-ip ::1 --on-port %d", pre6, g_ctx.port));
        } else {
            CHECK(run_cmd("ip6tables -w -t mangle -A %s -p udp -j TPROXY --on-ip ::1 --on-port %d", pre6, g_ctx.port));
            CHECK(run_cmd("ip6tables -w -t mangle -A %s -p tcp -j TPROXY --on-ip ::1 --on-port %d", pre6, g_ctx.port));
        }

        CHECK(init_chain("mangle", out6, "OUTPUT", "ip6tables", cg_match));
        CHECK(apply_bypass_rules(out6, "mangle", "ip6tables"));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p tcp -o lo ! --dport 53 -j RETURN", out6));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p udp -o lo ! --dport 53 -j RETURN", out6));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p tcp -j MARK --set-mark 0x%x", out6, g_ctx.tproxy_mark));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p udp -j MARK --set-mark 0x%x", out6, g_ctx.tproxy_mark));
    }

    if (g_ctx.override_dns[0] != '\0') {
        g_ctx.has_override_dns = 1;
        char dns4[128], dns6[128];

        if (is_valid_ipv4(g_ctx.override_dns)) {
            get_chain_name(dns4, sizeof(dns4), "TP_DNS", pid, false);
            CHECK(init_chain("nat", dns4, "OUTPUT", "iptables", cg_match));
            CHECK(apply_bypass_rules(dns4, "nat", "iptables"));
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp -o lo ! --dport 53 -j RETURN", dns4));
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -o lo ! --dport 53 -j RETURN", dns4));
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp --dport 53 -j DNAT --to-destination %s", dns4, g_ctx.override_dns));
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp --dport 53 -j DNAT --to-destination %s", dns4, g_ctx.override_dns));
        } else if (is_valid_ipv6(g_ctx.override_dns) && has_ip6tables()) {
            get_chain_name(dns6, sizeof(dns6), "TP_DNS", pid, true);
            CHECK(init_chain("nat", dns6, "OUTPUT", "ip6tables", cg_match));
            CHECK(apply_bypass_rules(dns6, "nat", "ip6tables"));
            CHECK(run_cmd("ip6tables -w -t nat -A %s -p udp -o lo ! --dport 53 -j RETURN", dns6));
            CHECK(run_cmd("ip6tables -w -t nat -A %s -p tcp -o lo ! --dport 53 -j RETURN", dns6));
            CHECK(run_cmd("ip6tables -w -t nat -A %s -p udp --dport 53 -j DNAT --to-destination %s", dns6, g_ctx.override_dns));
            CHECK(run_cmd("ip6tables -w -t nat -A %s -p tcp --dport 53 -j DNAT --to-destination %s", dns6, g_ctx.override_dns));
        }
    }
    return 0;
}

static int setup_trace(pid_t pid, const char *cg_match) {
    char out4[128], out6[128];
    get_chain_name(out4, sizeof(out4), "TR_OUT", pid, false);

    CHECK(init_chain("raw", out4, "OUTPUT", "iptables", cg_match));
    CHECK(apply_bypass_rules(out4, "raw", "iptables"));
    CHECK(run_cmd("iptables -w -t raw -A %s -j LOG --log-prefix \"cproxy: \"", out4));

    if (has_ip6tables()) {
        get_chain_name(out6, sizeof(out6), "TR_OUT", pid, true);
        CHECK(init_chain("raw", out6, "OUTPUT", "ip6tables", cg_match));
        CHECK(apply_bypass_rules(out6, "raw", "ip6tables"));
        CHECK(run_cmd("ip6tables -w -t raw -A %s -j LOG --log-prefix \"cproxy: \"", out6));
    }
    return 0;
}

int setup_iptables(pid_t pid) {
    char cg_match[256];
    get_cgroup_match(cg_match, sizeof(cg_match), pid);

    char mark_match[64];
    snprintf(mark_match, sizeof(mark_match), "-m mark --mark 0x%x", pid + 10000);

    switch (g_ctx.mode) {
        case MODE_REDIRECT: return setup_redirect(pid, cg_match);
        case MODE_TPROXY:   return setup_tproxy(pid, cg_match, mark_match);
        case MODE_TRACE:    return setup_trace(pid, cg_match);
    }
    return -1;
}

void cleanup_iptables(void) {
    pid_t pid = g_ctx.target_pid;
    if (pid <= 0) return;

    char cg_match[256];
    get_cgroup_match(cg_match, sizeof(cg_match), pid);

    char mark_match[64];
    snprintf(mark_match, sizeof(mark_match), "-m mark --mark 0x%x", pid + 10000);

    if (g_ctx.mode == MODE_REDIRECT) {
        char out4[128], out6[128];
        get_chain_name(out4, sizeof(out4), "RD_OUT", pid, false);
        destroy_chain("nat", out4, "OUTPUT", "iptables", cg_match);
        if (has_ip6tables()) {
            get_chain_name(out6, sizeof(out6), "RD_OUT", pid, true);
            destroy_chain("raw", out6, "OUTPUT", "ip6tables", cg_match);
        }
    } else if (g_ctx.mode == MODE_TPROXY) {
        char pre4[128], out4[128], pre6[128], out6[128];
        get_chain_name(pre4, sizeof(pre4), "TP_PRE", pid, false);
        get_chain_name(out4, sizeof(out4), "TP_OUT", pid, false);

        destroy_chain("mangle", pre4, "PREROUTING", "iptables", mark_match);
        destroy_chain("mangle", out4, "OUTPUT", "iptables", cg_match);

        if (has_ip6tables()) {
            get_chain_name(pre6, sizeof(pre6), "TP_PRE", pid, true);
            get_chain_name(out6, sizeof(out6), "TP_OUT", pid, true);
            destroy_chain("mangle", pre6, "PREROUTING", "ip6tables", mark_match);
            destroy_chain("mangle", out6, "OUTPUT", "ip6tables", cg_match);
        }

        if (g_ctx.has_override_dns) {
            char dns4[128], dns6[128];
            get_chain_name(dns4, sizeof(dns4), "TP_DNS", pid, false);
            destroy_chain("nat", dns4, "OUTPUT", "iptables", cg_match);
            if (has_ip6tables()) {
                get_chain_name(dns6, sizeof(dns6), "TP_DNS", pid, true);
                destroy_chain("nat", dns6, "OUTPUT", "ip6tables", cg_match);
            }
        }

        cleanup_tproxy_routing(g_ctx.tproxy_mark, AF_INET);
        if (has_ip6tables()) {
            cleanup_tproxy_routing(g_ctx.tproxy_mark, AF_INET6);
        }
    } else if (g_ctx.mode == MODE_TRACE) {
        char out4[128], out6[128];
        get_chain_name(out4, sizeof(out4), "TR_OUT", pid, false);
        destroy_chain("raw", out4, "OUTPUT", "iptables", cg_match);
        if (has_ip6tables()) {
            get_chain_name(out6, sizeof(out6), "TR_OUT", pid, true);
            destroy_chain("raw", out6, "OUTPUT", "ip6tables", cg_match);
        }
    }
}

static bool is_word_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
}

static bool is_exact_chain_match(const char *rule, const char *chain) {
    size_t chain_len = strlen(chain);
    const char *p = rule;
    while ((p = strstr(p, chain)) != NULL) {
        bool before_ok = (p == rule || !is_word_char(p[-1]));
        bool after_ok = (!is_word_char(p[chain_len]));
        if (before_ok && after_ok) return true;
        p += chain_len;
    }
    return false;
}

static void cleanup_chains_in_table(const char *table, const char *iptables_cmd) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s -t %s -S", iptables_cmd, table);

    FILE *fp = popen(cmd, "r");
    if (!fp) return;

    // First pass: Collect all rules and identify stale chains
    char **all_rules = NULL;
    int rule_count = 0;
    int rule_capacity = 0;

    char **stale_chains = NULL;
    int stale_count = 0;
    int stale_capacity = 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (rule_count >= rule_capacity) {
            rule_capacity = rule_capacity == 0 ? 64 : rule_capacity * 2;
            char **temp = realloc(all_rules, rule_capacity * sizeof(char *));
            if (!temp) {
                perror("realloc failed");
                break;
            }
            all_rules = temp;
        }
        all_rules[rule_count++] = strdup(line);

        if (strncmp(line, "-N CP", 5) == 0) {
            char name[64];
            if (sscanf(line + 3, "%63s", name) == 1) {
                char *last_underscore = strrchr(name, '_');
                if (last_underscore) {
                    pid_t pid = (pid_t)strtol(last_underscore + 1, NULL, 10);
                    if (pid > 0 && !is_pid_alive(pid)) {
                        if (stale_count >= stale_capacity) {
                            stale_capacity = stale_capacity == 0 ? 16 : stale_capacity * 2;
                            char **temp = realloc(stale_chains, stale_capacity * sizeof(char *));
                            if (!temp) {
                                perror("realloc failed");
                                break;
                            }
                            stale_chains = temp;
                        }
                        stale_chains[stale_count++] = strdup(name);
                    }
                }
            }
        }
    }
    pclose(fp);

    if (stale_count == 0) {
        if (all_rules) {
            for (int i = 0; i < rule_count; i++) free(all_rules[i]);
            free(all_rules);
        }
        return;
    }

    // Second pass: Delete references to stale chains
    for (int i = 0; i < stale_count; i++) {
        log_debug("Cleaning up stale chain %s in table %s", stale_chains[i], table);
        for (int j = 0; j < rule_count; j++) {
            if (strncmp(all_rules[j], "-A ", 3) == 0 && is_exact_chain_match(all_rules[j], stale_chains[i])) {
                char prefix[128];
                snprintf(prefix, sizeof(prefix), "-A %s ", stale_chains[i]);
                if (strncmp(all_rules[j], prefix, strlen(prefix)) != 0) {
                    run_cmd_silent("%s -t %s -D %s", iptables_cmd, table, all_rules[j] + 3);
                }
            }
        }
    }

    // Final pass: Flush and delete stale chains
    for (int i = 0; i < stale_count; i++) {
        run_cmd_silent("%s -t %s -F %s", iptables_cmd, table, stale_chains[i]);
        run_cmd_silent("%s -t %s -X %s", iptables_cmd, table, stale_chains[i]);
        free(stale_chains[i]);
    }

    if (all_rules) {
        for (int i = 0; i < rule_count; i++) free(all_rules[i]);
        free(all_rules);
    }
    free(stale_chains);
}

static void cleanup_stale_ip_rules(void) {
    const char* cmds[] = {"ip", "ip -6"};
    for (int i = 0; i < 2; i++) {
        char list_cmd[64];
        snprintf(list_cmd, sizeof(list_cmd), "%s rule show", cmds[i]);
        FILE *fp = popen(list_cmd, "r");
        if (!fp) continue;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            unsigned int mark = 0, table = 0;
            char *p;
            // Handle both "lookup" and "table" keywords which are synonyms in ip-rule
            if ((p = strstr(line, "fwmark 0x")) && sscanf(p + 9, "%x", &mark) == 1) {
                if (((p = strstr(line, "lookup ")) && sscanf(p + 7, "%u", &table) == 1) ||
                    ((p = strstr(line, "table ")) && sscanf(p + 6, "%u", &table) == 1)) {
                    if (mark == table && mark >= 10000) {
                        pid_t pid = (pid_t)(mark - 10000);
                        if (is_pid_alive(pid)) continue;

                        log_debug("Cleaning up stale ip rule for mark 0x%x", mark);
                        run_cmd_silent("%s rule delete fwmark 0x%x table %u", cmds[i], mark, table);
                        run_cmd_silent("%s route flush table %u", cmds[i], table);
                    }
                }
            }
        }
        pclose(fp);
    }
}

void cleanup_stale_iptables(void) {
    const char *tables[] = {"nat", "mangle", "raw", "filter"};
    for (int i = 0; i < 4; i++) {
        cleanup_chains_in_table(tables[i], "iptables");
        if (has_ip6tables()) {
            cleanup_chains_in_table(tables[i], "ip6tables");
        }
    }

    cleanup_stale_ip_rules();
}
