#include "cproxy.h"

// Global context
Context g_ctx = {
    .port = 1080,
    .dns_port = 0,
    .redirect_dns = false,
    .mode = MODE_REDIRECT,
    .verbose = false,
    .dry_run = false,
    .tproxy_mark = 0,
    .cgroup_created = false,
    .target_pid = 0,
    .is_v2 = false,
    .clean_stale = false
};

volatile sig_atomic_t g_keep_running = 1;

void sig_handler(int sig) {
    (void)sig;
    g_keep_running = 0;
}

void do_clean_stale(void) {
    log_info("Cleaning up stale iptables rules and cgroups...");
    cleanup_stale_iptables();
    cleanup_stale_cgroups();
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
    if (g_ctx.bypass_rules) {
        free(g_ctx.bypass_rules);
        g_ctx.bypass_rules = NULL;
    }
}

int main(int argc, char *argv[]) {
    atexit(cleanup);

    if (parse_args(&g_ctx, argc, argv) != 0) return 1;
    if (parse_bypass_rules(&g_ctx) != 0) return 1;

    if (!g_ctx.dry_run && geteuid() != 0) {
        log_error("cproxy must be run as root (use sudo)");
        return 1;
    }

    if (check_dependencies() != 0) return 1;

    if (init_cgroup_support() != 0) return 1;

    if (g_ctx.clean_stale) {
        do_clean_stale();
        return 0;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sa.sa_flags = 0; // Disable SA_RESTART so waitpid can be interrupted by signals
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    if (g_ctx.verbose) {
        const char *mode_str = (g_ctx.mode == MODE_REDIRECT) ? "redirect" : (g_ctx.mode == MODE_TPROXY ? "tproxy" : "trace");
        log_info("Detected Cgroup v%d mode", g_ctx.is_v2 ? 2 : 1);
        log_info("Mode: %s, Port: %d (DNS: %d)", mode_str, g_ctx.port, g_ctx.dns_port);
        if (g_ctx.mode == MODE_REDIRECT)
            log_info("Redirect DNS: %s", g_ctx.redirect_dns ? "on" : "off");
        if (g_ctx.bypass_str) log_info("Bypass: %s", g_ctx.bypass_str);
        if (g_ctx.override_dns[0])
            log_info("Override DNS: %s", g_ctx.override_dns);
    }

    bool is_attaching = (g_ctx.target_pid > 0);
    int pipefd[2] = {-1, -1};
    pid_t child_pid = 0;

    if (!is_attaching) {
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
            ssize_t nread;
            while ((nread = read(pipefd[0], &sync_buf, 1)) == -1 && errno == EINTR);
            if (nread <= 0)
                _exit(1);
            close(pipefd[0]);

            drop_privileges();

            char env_str[64];
            snprintf(env_str, sizeof(env_str), "cproxy/%d", g_ctx.port);
            setenv("CPROXY_ENV", env_str, 1);
            execvp(argv[optind], &argv[optind]);
            perror("execvp failed");
            _exit(1);
        }
        close(pipefd[0]);
    }

    pid_t process_to_proxy = is_attaching ? g_ctx.target_pid : child_pid;

    if (is_attaching && check_process_ownership(process_to_proxy) != 0) {
        if (!is_attaching) close(pipefd[1]); // Just in case, though it's is_attaching
        return 1;
    }

    g_ctx.target_pid = process_to_proxy; // Ensure cleanup knows which PID to use

    if (setup_cgroup(process_to_proxy) != 0 || setup_iptables(process_to_proxy) != 0) {
        if (!is_attaching) close(pipefd[1]);
        return 1;
    }

    if (is_attaching) {
        printf("Proxying PID %d. Press Ctrl+C to stop...\n", g_ctx.target_pid);
        wait_for_process(g_ctx.target_pid);
    } else {
        ssize_t nwritten;
        while ((nwritten = write(pipefd[1], "A", 1)) == -1 && errno == EINTR);
        if (nwritten != 1) perror("Sync failed");
        close(pipefd[1]);

        int status = 0;
        while (g_keep_running) {
            int r = waitpid(child_pid, &status, 0);
            if (r == child_pid) break;
            if (r == -1 && errno != EINTR) break;
        }

        if (!g_keep_running && kill(child_pid, 0) == 0) {
            kill(child_pid, SIGTERM);
            int wait_attempts = 30; // 3 seconds
            while (wait_attempts-- > 0) {
                int r = waitpid(child_pid, &status, WNOHANG);
                if (r == child_pid) break;
                if (r == -1 && errno != EINTR) break;
                usleep(100000);
            }
            if (kill(child_pid, 0) == 0) {
                log_warn("Child process did not exit after SIGTERM, sending SIGKILL...");
                kill(child_pid, SIGKILL);
                while (waitpid(child_pid, &status, 0) == -1 && errno == EINTR);
            }
        }

        int wait_timeout = 50; // 5s
        while (!is_cgroup_empty() && wait_timeout-- > 0) usleep(100000);

        return WIFEXITED(status) ? WEXITSTATUS(status) : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 0);
    }

    return 0;
}
