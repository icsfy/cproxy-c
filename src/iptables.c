#include "cproxy.h"

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
                CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --path %s --dport 53 -j REDIRECT --to-ports %d", g_ctx.output_chain, relative_cg_path, g_ctx.port));
            }
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -j DROP", out6_chain, relative_cg_path);
        } else {
            CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --cgroup 0x%08x -j REDIRECT --to-ports %d", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.port));
            if (g_ctx.redirect_dns) {
                CHECK(run_cmd("iptables -w -t nat -A %s -p udp -m cgroup --cgroup 0x%08x --dport 53 -j REDIRECT --to-ports %d", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.port));
                CHECK(run_cmd("iptables -w -t nat -A %s -p tcp -m cgroup --cgroup 0x%08x --dport 53 -j REDIRECT --to-ports %d", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF), g_ctx.port));
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
            CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --path %s -j LOG --log-prefix \"cproxy: \"", g_ctx.output_chain, relative_cg_path));
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --path %s -j LOG --log-prefix \"cproxy: \"", out6_chain, relative_cg_path);
        } else {
            CHECK(run_cmd("iptables -w -t raw -A %s -m cgroup --cgroup 0x%08x -j LOG --log-prefix \"cproxy: \"", g_ctx.output_chain, (1 << 16) | (pid & 0xFFFF)));
            run_cmd_silent("ip6tables -w -t raw -A %s -m cgroup --cgroup 0x%08x -j LOG --log-prefix \"cproxy: \"", out6_chain, (1 << 16) | (pid & 0xFFFF));
        }
    }
    return 0;
}

void cleanup_iptables(void) {
    int pid = (int)g_ctx.target_pid;
    if (pid <= 0) return;

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
