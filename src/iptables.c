#include "cproxy.h"

#define CHECK(x) do { if ((x) != 0) return -1; } while (0)

static int setup_tproxy_routing(int mark, int family) {
    const char *ip_cmd = (family == AF_INET6) ? "ip -6" : "ip";
    const char *any_addr = (family == AF_INET6) ? "::/0" : "0.0.0.0/0";

    if (g_ctx.verbose) printf("[INFO] Setting up TProxy routing for %s (mark: 0x%x)\n",
                               (family == AF_INET6) ? "IPv6" : "IPv4", mark);

    run_cmd_silent("%s rule delete fwmark 0x%x table %d", ip_cmd, mark, mark);
    run_cmd_silent("%s route delete local %s dev lo table %d", ip_cmd, any_addr, mark);

    CHECK(run_cmd("%s rule add fwmark 0x%x table %d", ip_cmd, mark, mark));
    CHECK(run_cmd("%s route add local %s dev lo table %d", ip_cmd, any_addr, mark));
    return 0;
}

static void cleanup_tproxy_routing(int mark, int family) {
    const char *ip_cmd = (family == AF_INET6) ? "ip -6" : "ip";
    const char *any_addr = (family == AF_INET6) ? "::/0" : "0.0.0.0/0";
    if (mark == 0) return;
    run_cmd_silent("%s rule delete fwmark 0x%x table %d", ip_cmd, mark, mark);
    run_cmd_silent("%s route delete local %s dev lo table %d", ip_cmd, any_addr, mark);
}

int init_chain(const char *table, const char *chain, const char *parent, const char *iptables_cmd, const char *match) {
    if (match && strlen(match) > 0) {
        run_cmd_silent("%s -w -t %s -D %s %s -j %s", iptables_cmd, table, parent, match, chain);
    } else {
        run_cmd_silent("%s -w -t %s -D %s -j %s", iptables_cmd, table, parent, chain);
    }
    run_cmd_silent("%s -w -t %s -F %s", iptables_cmd, table, chain);
    run_cmd_silent("%s -w -t %s -X %s", iptables_cmd, table, chain);

    CHECK(run_cmd("%s -w -t %s -N %s", iptables_cmd, table, chain));
    if (match && strlen(match) > 0) {
        CHECK(run_cmd("%s -w -t %s -A %s %s -j %s", iptables_cmd, table, parent, match, chain));
    } else {
        CHECK(run_cmd("%s -w -t %s -A %s -j %s", iptables_cmd, table, parent, chain));
    }
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

static void get_cgroup_match(char *buf, size_t len, const char *relative_cg_path, pid_t pid) {
    if (g_ctx.is_v2) {
        snprintf(buf, len, "-m cgroup --path %s", relative_cg_path);
    } else {
        unsigned int classid = (((unsigned int)(pid >> 16) + 1) << 16) | (pid & 0xFFFF);
        snprintf(buf, len, "-m cgroup --cgroup 0x%08x", classid);
    }
}

int setup_iptables(pid_t pid) {
    char relative_cg_path[PATH_MAX] = {0};
    if (g_ctx.is_v2) snprintf(relative_cg_path, sizeof(relative_cg_path), "/cproxy-%d", pid);

    char cg_match[256];
    get_cgroup_match(cg_match, sizeof(cg_match), relative_cg_path, pid);

    char mark_match[64];
    snprintf(mark_match, sizeof(mark_match), "-m mark --mark 0x%x", pid + 10000);

    if (g_ctx.mode == MODE_REDIRECT) {
        snprintf(g_ctx.output_chain, sizeof(g_ctx.output_chain), "CP_RD_OUT_%d", pid);
        char out6_chain[128];
        snprintf(out6_chain, sizeof(out6_chain), "CP6_RD_OUT_%d", pid);

        CHECK(init_chain("nat", g_ctx.output_chain, "OUTPUT", "iptables", cg_match));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, g_ctx.output_chain, "nat", "iptables"));

        // Exclude traffic on loopback that isn't DNS
        CHECK(run_cmd("iptables -w -t nat -A %s -o lo ! --dport 53 -j RETURN", g_ctx.output_chain));

        if (!g_ctx.redirect_dns) {
            // Specifically bypass DNS if not redirecting
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp --dport 53 -j RETURN", g_ctx.output_chain));
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp --dport 53 -j RETURN", g_ctx.output_chain));
        }

        CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -j REDIRECT --to-ports %d", g_ctx.output_chain, g_ctx.port));
        if (g_ctx.redirect_dns) {
            CHECK(run_cmd("iptables -w -t nat -A %s -p udp --dport 53 -j REDIRECT --to-ports %d", g_ctx.output_chain, g_ctx.port));
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp --dport 53 -j REDIRECT --to-ports %d", g_ctx.output_chain, g_ctx.port));
        }

        // IPv6: drop all outbound traffic from the process to prevent leaks in redirect mode
        CHECK(init_chain("raw", out6_chain, "OUTPUT", "ip6tables", cg_match));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, out6_chain, "raw", "ip6tables"));
        run_cmd_silent("ip6tables -w -t raw -A %s -o lo -j RETURN", out6_chain);
        run_cmd_silent("ip6tables -w -t raw -A %s -j DROP", out6_chain);

    } else if (g_ctx.mode == MODE_TPROXY) {
        g_ctx.tproxy_mark = pid + 10000;
        char pre4[128], out4[128], pre6[128], out6[128];
        snprintf(out4, sizeof(out4), "CP_TP_OUT_%d", pid);
        snprintf(pre4, sizeof(pre4), "CP_TP_PRE_%d", pid);
        snprintf(out6, sizeof(out6), "CP6_TP_OUT_%d", pid);
        snprintf(pre6, sizeof(pre6), "CP6_TP_PRE_%d", pid);

        CHECK(setup_tproxy_routing(g_ctx.tproxy_mark, AF_INET));
        CHECK(setup_tproxy_routing(g_ctx.tproxy_mark, AF_INET6));

        // IPv4 TProxy
        CHECK(init_chain("mangle", pre4, "PREROUTING", "iptables", mark_match));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, pre4, "mangle", "iptables"));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -j TPROXY --on-ip 127.0.0.1 --on-port %d", pre4, g_ctx.port));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port %d", pre4, g_ctx.port));

        CHECK(init_chain("mangle", out4, "OUTPUT", "iptables", cg_match));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, out4, "mangle", "iptables"));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -o lo ! --dport 53 -j RETURN", out4));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -o lo ! --dport 53 -j RETURN", out4));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p tcp -j MARK --set-mark 0x%x", out4, g_ctx.tproxy_mark));
        CHECK(run_cmd("iptables -w -t mangle -A %s -p udp -j MARK --set-mark 0x%x", out4, g_ctx.tproxy_mark));

        // IPv6 TProxy
        CHECK(init_chain("mangle", pre6, "PREROUTING", "ip6tables", mark_match));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, pre6, "mangle", "ip6tables"));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p udp -j TPROXY --on-ip ::1 --on-port %d", pre6, g_ctx.port));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p tcp -j TPROXY --on-ip ::1 --on-port %d", pre6, g_ctx.port));

        CHECK(init_chain("mangle", out6, "OUTPUT", "ip6tables", cg_match));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, out6, "mangle", "ip6tables"));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p tcp -o lo ! --dport 53 -j RETURN", out6));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p udp -o lo ! --dport 53 -j RETURN", out6));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p tcp -j MARK --set-mark 0x%x", out6, g_ctx.tproxy_mark));
        CHECK(run_cmd("ip6tables -w -t mangle -A %s -p udp -j MARK --set-mark 0x%x", out6, g_ctx.tproxy_mark));

        if (g_ctx.override_dns[0] != '\0') {
            g_ctx.has_override_dns = 1;
            char dns4[128], dns6[128];
            snprintf(dns4, sizeof(dns4), "CP_TP_DNS_%d", pid);
            snprintf(dns6, sizeof(dns6), "CP6_TP_DNS_%d", pid);

            if (is_valid_ipv4(g_ctx.override_dns)) {
                CHECK(init_chain("nat", dns4, "OUTPUT", "iptables", cg_match));
                CHECK(apply_bypass_rules(g_ctx.bypass_str, dns4, "nat", "iptables"));
                CHECK(run_cmd("iptables -w -t nat -A %s -o lo ! --dport 53 -j RETURN", dns4));
                CHECK(run_cmd("iptables -w -t nat -A %s -p udp --dport 53 -j DNAT --to-destination %s", dns4, g_ctx.override_dns));
                CHECK(run_cmd("iptables -w -t nat -A %s -p tcp --dport 53 -j DNAT --to-destination %s", dns4, g_ctx.override_dns));
            } else if (is_valid_ipv6(g_ctx.override_dns)) {
                CHECK(init_chain("nat", dns6, "OUTPUT", "ip6tables", cg_match));
                CHECK(apply_bypass_rules(g_ctx.bypass_str, dns6, "nat", "ip6tables"));
                CHECK(run_cmd("ip6tables -w -t nat -A %s -o lo ! --dport 53 -j RETURN", dns6));
                CHECK(run_cmd("ip6tables -w -t nat -A %s -p udp --dport 53 -j DNAT --to-destination %s", dns6, g_ctx.override_dns));
                CHECK(run_cmd("ip6tables -w -t nat -A %s -p tcp --dport 53 -j DNAT --to-destination %s", dns6, g_ctx.override_dns));
            }
        }
    } else if (g_ctx.mode == MODE_TRACE) {
        char out4[128], out6[128];
        snprintf(out4, sizeof(out4), "CP_TR_OUT_%d", pid);
        snprintf(out6, sizeof(out6), "CP6_TR_OUT_%d", pid);

        CHECK(init_chain("raw", out4, "OUTPUT", "iptables", cg_match));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, out4, "raw", "iptables"));
        CHECK(run_cmd("iptables -w -t raw -A %s -j LOG --log-prefix \"cproxy: \"", out4));

        CHECK(init_chain("raw", out6, "OUTPUT", "ip6tables", cg_match));
        CHECK(apply_bypass_rules(g_ctx.bypass_str, out6, "raw", "ip6tables"));
        run_cmd_silent("ip6tables -w -t raw -A %s -j LOG --log-prefix \"cproxy: \"", out6);
    }
    return 0;
}

void cleanup_iptables(void) {
    int pid = (int)g_ctx.target_pid;
    if (pid <= 0) return;

    char relative_cg_path[PATH_MAX] = {0};
    if (g_ctx.is_v2) snprintf(relative_cg_path, sizeof(relative_cg_path), "/cproxy-%d", pid);
    char cg_match[256];
    get_cgroup_match(cg_match, sizeof(cg_match), relative_cg_path, pid);

    char mark_match[64];
    snprintf(mark_match, sizeof(mark_match), "-m mark --mark 0x%x", pid + 10000);

    if (g_ctx.mode == MODE_REDIRECT) {
        char out4[128], out6[128];
        snprintf(out4, sizeof(out4), "CP_RD_OUT_%d", pid);
        snprintf(out6, sizeof(out6), "CP6_RD_OUT_%d", pid);

        run_cmd_silent("iptables -w -t nat -D OUTPUT %s -j %s", cg_match, out4);
        run_cmd_silent("iptables -w -t nat -F %s", out4);
        run_cmd_silent("iptables -w -t nat -X %s", out4);

        run_cmd_silent("ip6tables -w -t raw -D OUTPUT %s -j %s", cg_match, out6);
        run_cmd_silent("ip6tables -w -t raw -F %s", out6);
        run_cmd_silent("ip6tables -w -t raw -X %s", out6);
    } else if (g_ctx.mode == MODE_TPROXY) {
        char out4[128], pre4[128], out6[128], pre6[128];
        snprintf(out4, sizeof(out4), "CP_TP_OUT_%d", pid);
        snprintf(pre4, sizeof(pre4), "CP_TP_PRE_%d", pid);
        snprintf(out6, sizeof(out6), "CP6_TP_OUT_%d", pid);
        snprintf(pre6, sizeof(pre6), "CP6_TP_PRE_%d", pid);

        run_cmd_silent("iptables -w -t mangle -D PREROUTING %s -j %s", mark_match, pre4);
        run_cmd_silent("iptables -w -t mangle -F %s", pre4);
        run_cmd_silent("iptables -w -t mangle -X %s", pre4);

        run_cmd_silent("iptables -w -t mangle -D OUTPUT %s -j %s", cg_match, out4);
        run_cmd_silent("iptables -w -t mangle -F %s", out4);
        run_cmd_silent("iptables -w -t mangle -X %s", out4);

        run_cmd_silent("ip6tables -w -t mangle -D PREROUTING %s -j %s", mark_match, pre6);
        run_cmd_silent("ip6tables -w -t mangle -F %s", pre6);
        run_cmd_silent("ip6tables -w -t mangle -X %s", pre6);

        run_cmd_silent("ip6tables -w -t mangle -D OUTPUT %s -j %s", cg_match, out6);
        run_cmd_silent("ip6tables -w -t mangle -F %s", out6);
        run_cmd_silent("ip6tables -w -t mangle -X %s", out6);

        if (g_ctx.has_override_dns) {
            char dns4[128], dns6[128];
            snprintf(dns4, sizeof(dns4), "CP_TP_DNS_%d", pid);
            snprintf(dns6, sizeof(dns6), "CP6_TP_DNS_%d", pid);

            run_cmd_silent("iptables -w -t nat -D OUTPUT %s -j %s", cg_match, dns4);
            run_cmd_silent("iptables -w -t nat -F %s", dns4);
            run_cmd_silent("iptables -w -t nat -X %s", dns4);

            run_cmd_silent("ip6tables -w -t nat -D OUTPUT %s -j %s", cg_match, dns6);
            run_cmd_silent("ip6tables -w -t nat -F %s", dns6);
            run_cmd_silent("ip6tables -w -t nat -X %s", dns6);
        }

        cleanup_tproxy_routing(g_ctx.tproxy_mark, AF_INET);
        cleanup_tproxy_routing(g_ctx.tproxy_mark, AF_INET6);
    } else if (g_ctx.mode == MODE_TRACE) {
        char out4[128], out6[128];
        snprintf(out4, sizeof(out4), "CP_TR_OUT_%d", pid);
        snprintf(out6, sizeof(out6), "CP6_TR_OUT_%d", pid);

        run_cmd_silent("iptables -w -t raw -D OUTPUT %s -j %s", cg_match, out4);
        run_cmd_silent("iptables -w -t raw -F %s", out4);
        run_cmd_silent("iptables -w -t raw -X %s", out4);

        run_cmd_silent("ip6tables -w -t raw -D OUTPUT %s -j %s", cg_match, out6);
        run_cmd_silent("ip6tables -w -t raw -F %s", out6);
        run_cmd_silent("ip6tables -w -t raw -X %s", out6);
    }
}
