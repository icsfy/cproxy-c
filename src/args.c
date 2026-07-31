#include "cproxy.h"

int parse_args(Context *ctx, int argc, char *argv[]) {
    char mode_str[32] = "redirect";
    struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"dns-port", required_argument, 0, 'l'},
        {"redirect-dns", no_argument, 0, 'd'},
        {"mode", required_argument, 0, 'm'},
        {"override-dns", required_argument, 0, 'o'},
        {"pid", required_argument, 0, 'i'},
        {"bypass", required_argument, 0, 'b'},
        {"verbose", no_argument, 0, 'V'},
        {"dry-run", no_argument, 0, 'D'},
        {"clean", no_argument, 0, 'C'},
        {"hosts", required_argument, 0, 'H'},
        {"resolvconf", required_argument, 0, 'R'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:l:dm:o:i:b:H:R:VDChv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v': printf("cproxy version %s\n", CPROXY_VERSION); exit(0);
            case 'h':
                fprintf(stderr, "Usage: %s [options] -- <command...>\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  -p, --port <port>         Proxy port (default: 1080)\n");
                fprintf(stderr, "  -l, --dns-port <port>     DNS proxy port (default: same as --port)\n");
                fprintf(stderr, "  -m, --mode <mode>         Mode: redirect (default), tproxy, trace\n");
                fprintf(stderr, "  -d, --redirect-dns        Redirect DNS in redirect mode\n");
                fprintf(stderr, "  -o, --override-dns <ip>   Override DNS IP (DNAT/TProxy)\n");
                fprintf(stderr, "  -b, --bypass <ips>        Comma-separated list of IPs/CIDRs to bypass\n");
                fprintf(stderr, "  -i, --pid <pid>           Attach to an existing process\n");
                fprintf(stderr, "  -H, --hosts <file>        Bind mount a custom file over /etc/hosts\n");
                fprintf(stderr, "  -R, --resolvconf <file>   Bind mount a custom file over /etc/resolv.conf\n");
                fprintf(stderr, "  -V, --verbose             Show detailed debug information\n");
                fprintf(stderr, "  -D, --dry-run             Show commands without executing them\n");
                fprintf(stderr, "  -C, --clean               Cleanup stale iptables rules and cgroups\n");
                fprintf(stderr, "  -h, --help                Show this help message\n");
                fprintf(stderr, "  -v, --version             Show version information\n");
                exit(0);
            case 'p': {
                char *endptr;
                long p = strtol(optarg, &endptr, 10);
                if (*optarg == '\0' || *endptr != '\0' || p <= 0 || p > 65535) {
                    fprintf(stderr, "Error: Invalid port: %s\n", optarg);
                    return -1;
                }
                ctx->port = (int)p;
                break;
            }
            case 'l': {
                char *endptr;
                long p = strtol(optarg, &endptr, 10);
                if (*optarg == '\0' || *endptr != '\0' || p <= 0 || p > 65535) {
                    fprintf(stderr, "Error: Invalid DNS port: %s\n", optarg);
                    return -1;
                }
                ctx->dns_port = (int)p;
                break;
            }
            case 'd': ctx->redirect_dns = true; break;
            case 'm': snprintf(mode_str, sizeof(mode_str), "%s", optarg); break;
            case 'V': ctx->verbose = true; break;
            case 'D': ctx->dry_run = true; break;
            case 'C': ctx->clean_stale = true; break;
            case 'H':
                if (realpath(optarg, ctx->custom_hosts) == NULL) {
                    fprintf(stderr, "Error: Invalid or inaccessible hosts file: %s\n", optarg);
                    return -1;
                }
                ctx->has_custom_hosts = true;
                break;
            case 'R':
                if (realpath(optarg, ctx->custom_resolvconf) == NULL) {
                    fprintf(stderr, "Error: Invalid or inaccessible resolvconf file: %s\n", optarg);
                    return -1;
                }
                ctx->has_custom_resolvconf = true;
                break;
            case 'o':
                if (is_valid_ipv4(optarg) || is_valid_ipv6(optarg)) {
                    snprintf(ctx->override_dns, sizeof(ctx->override_dns), "%s", optarg);
                    ctx->has_override_dns = true;
                } else {
                    fprintf(stderr, "Error: Invalid IP address for --override-dns\n");
                    return -1;
                }
                break;
            case 'i': {
                char *endptr;
                long p = strtol(optarg, &endptr, 10);
                if (*optarg == '\0' || *endptr != '\0' || p <= 0) {
                    fprintf(stderr, "Error: Invalid PID: %s\n", optarg);
                    return -1;
                }
                ctx->target_pid = (pid_t)p;
                break;
            }
            case 'b':
                if (is_valid_bypass_str(optarg)) {
                    if (ctx->bypass_str) {
                        char *old = ctx->bypass_str;
                        if (asprintf(&ctx->bypass_str, "%s,%s", old, optarg) == -1) {
                            perror("asprintf failed");
                            ctx->bypass_str = old;
                            return -1;
                        }
                        free(old);
                    } else {
                        ctx->bypass_str = strdup(optarg);
                        if (!ctx->bypass_str) {
                            perror("strdup failed");
                            return -1;
                        }
                    }
                } else {
                    fprintf(stderr, "Error: Invalid --bypass string\n");
                    return -1;
                }
                break;
            default: return -1;
        }
    }

    if (strcmp(mode_str, "redirect") == 0) ctx->mode = MODE_REDIRECT;
    else if (strcmp(mode_str, "tproxy") == 0) ctx->mode = MODE_TPROXY;
    else if (strcmp(mode_str, "trace") == 0) ctx->mode = MODE_TRACE;
    else {
        fprintf(stderr, "Unknown mode: %s\n", mode_str);
        return -1;
    }

    if (ctx->dns_port == 0) ctx->dns_port = ctx->port;

    if (ctx->clean_stale) return 0;

    if (ctx->target_pid == 0 && optind >= argc) {
        fprintf(stderr, "Error: No command specified and no --pid provided.\n");
        return -1;
    }

    if ((ctx->has_custom_hosts || ctx->has_custom_resolvconf) && ctx->target_pid > 0) {
        fprintf(stderr, "Error: --hosts and --resolvconf cannot be used with --pid (already running processes).\n");
        return -1;
    }

    if (!ctx->bypass_str) {
        char *env_bypass = getenv("CPROXY_BYPASS");
        if (env_bypass && is_valid_bypass_str(env_bypass)) ctx->bypass_str = strdup(env_bypass);
    }

    return 0;
}
