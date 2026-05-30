#include "cproxy.h"

int run_cmd_v(const char *fmt, va_list args, int silent) {
    char cmd_buf[4096];
    int n = vsnprintf(cmd_buf, sizeof(cmd_buf), fmt, args);
    if (n < 0 || n >= (int)sizeof(cmd_buf)) {
        if (!silent) fprintf(stderr, "Error: Command too long\n");
        return -1;
    }

    double start = 0;
    if (g_ctx.verbose || g_ctx.dry_run) {
        printf("[DEBUG] Executing: %s\n", cmd_buf);
        if (g_ctx.dry_run) return 0;
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
