#include "cproxy.h"

// Global context
Context g_ctx = {
    .port = 1080,
    .redirect_dns = false,
    .mode = MODE_REDIRECT,
    .verbose = false,
    .dry_run = false,
    .tproxy_mark = 0,
    .cgroup_created = false,
    .target_pid = 0
};

volatile sig_atomic_t g_keep_running = 1;

void sig_handler(int sig) {
    (void)sig;
    g_keep_running = 0;
}

void cleanup(void) {
    static int cleaned_up = 0;
    if (cleaned_up) return;
    cleaned_up = 1;

    sigset_t set;
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, NULL);

    cleanup_iptables();
    cleanup_cgroup();

    if (g_ctx.bypass_str) {
        free(g_ctx.bypass_str);
        g_ctx.bypass_str = NULL;
    }
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
        {"dry-run", no_argument, 0, 'D'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    int ret = 0;
    while ((opt = getopt_long(argc, argv, "p:dm:o:i:b:VDhv", long_options, &option_index)) != -1) {
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
                fprintf(stderr, "  -D, --dry-run             Show commands without executing them\n");
                fprintf(stderr, "  -h, --help                Show this help message\n");
                return 0;
            case 'p': {
                int p = atoi(optarg);
                if (p <= 0 || p > 65535) {
                    fprintf(stderr, "Error: Invalid port: %s\n", optarg);
                    return 1;
                }
                g_ctx.port = p;
                break;
            }
            case 'd': g_ctx.redirect_dns = 1; break;
            case 'm': snprintf(mode_str, sizeof(mode_str), "%s", optarg); break;
            case 'V': g_ctx.verbose = 1; break;
            case 'D': g_ctx.dry_run = 1; break;
            case 'o':
                if (is_valid_ipv4(optarg)) {
                    snprintf(g_ctx.override_dns, sizeof(g_ctx.override_dns), "%s", optarg);
                } else {
                    fprintf(stderr, "Error: Invalid IPv4 address for --override-dns\n");
                    ret = 1; goto cleanup_all;
                }
                break;
            case 'i': {
                pid_t p = (pid_t)atoi(optarg);
                if (p <= 0) {
                    fprintf(stderr, "Error: Invalid PID: %s\n", optarg);
                    return 1;
                }
                target_pid = p;
                break;
            }
            case 'b':
                if (is_valid_bypass_str(optarg)) {
                    if (g_ctx.bypass_str) {
                        char *old = g_ctx.bypass_str;
                        if (asprintf(&g_ctx.bypass_str, "%s,%s", old, optarg) == -1) {
                            perror("asprintf failed");
                            g_ctx.bypass_str = old; // Restore to avoid double free if we were to handle it differently, but here we exit
                            ret = 1; goto cleanup_all;
                        }
                        free(old);
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

    if (g_ctx.verbose) {
        printf("[INFO] Detected Cgroup v%d mode\n", g_ctx.is_v2 ? 2 : 1);
        printf("[INFO] Mode: %s, Port: %d\n", mode_str, g_ctx.port);
        if (g_ctx.bypass_str) printf("[INFO] Bypass: %s\n", g_ctx.bypass_str);
        if (g_ctx.mode == MODE_TPROXY && g_ctx.override_dns[0])
            printf("[INFO] Override DNS: %s\n", g_ctx.override_dns);
    }

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
