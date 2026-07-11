#include "cproxy.h"

static void exec_cmd(char *cmd_buf) {
    char *argv_cmd[128];
    int argc_cmd = 0;
    char *p = cmd_buf;
    while (*p && argc_cmd < 127) {
        while (*p == ' ') p++;
        if (!*p) break;

        if (*p == '\'') {
            p++;
            argv_cmd[argc_cmd++] = p;
            while (*p && *p != '\'') p++;
            if (*p == '\'') {
                *p = '\0';
                p++;
            }
        } else if (*p == '"') {
            p++;
            argv_cmd[argc_cmd++] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') {
                *p = '\0';
                p++;
            }
        } else {
            argv_cmd[argc_cmd++] = p;
            while (*p && *p != ' ' && *p != '\'' && *p != '"') p++;
            if (*p == ' ' || *p == '\'' || *p == '"') {
                char next = *p;
                *p = '\0';
                p++;
                if (next != ' ') {
                    // This handles cases where quotes are attached to words,
                    // but in cproxy we separate arguments by spaces.
                }
            }
        }
    }
    argv_cmd[argc_cmd] = NULL;

    if (argc_cmd > 0) {
        execvp(argv_cmd[0], argv_cmd);
    }
    _exit(127);
}

int run_cmd_v(const char *fmt, va_list args, int silent) {
    char cmd_buf[4096];
    int n = vsnprintf(cmd_buf, sizeof(cmd_buf), fmt, args);
    if (n < 0 || n >= (int)sizeof(cmd_buf)) {
        if (!silent) log_error("Command too long");
        return -1;
    }

    double start = 0;
    if (g_ctx.verbose || g_ctx.dry_run) {
        log_debug("Executing: %s", cmd_buf);
        if (g_ctx.dry_run) return 0;
        start = get_time_ms();
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Reset signal mask so child processes aren't stuck with blocked signals
        // (important when called from cleanup() which blocks all signals)
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);

        // If cproxy is setuid root, bash will drop privileges back to the real UID unless
        // we explicitly set the real UID to match the effective UID (0).
        if (setuid(geteuid()) != 0) {
            perror("setuid failed in run_cmd");
        }
        if (setgid(getegid()) != 0) {
            perror("setgid failed in run_cmd");
        }

        clearenv();
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        if (silent && !g_ctx.verbose) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull != -1) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        exec_cmd(cmd_buf);
        _exit(127);
    } else if (pid > 0) {
        int status;
        while (waitpid(pid, &status, 0) == -1) {
            if (errno != EINTR) {
                if (!silent || g_ctx.verbose) perror("waitpid failed");
                return -1;
            }
        }

        int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (g_ctx.verbose) {
            double end = get_time_ms();
            if (WIFEXITED(status)) {
                log_debug("Command took %.2fms, exit code: %d", end - start, exit_code);
            } else if (WIFSIGNALED(status)) {
                log_debug("Command took %.2fms, terminated by signal: %d", end - start, WTERMSIG(status));
            } else {
                log_debug("Command took %.2fms, terminated abnormally", end - start);
            }
        }

        if (exit_code != 0) {
            if (!silent || g_ctx.verbose) {
                if (WIFEXITED(status)) {
                    log_error("Command returned %d: %s", exit_code, cmd_buf);
                } else if (WIFSIGNALED(status)) {
                    log_error("Command killed by signal %d: %s", WTERMSIG(status), cmd_buf);
                } else {
                    log_error("Command failed: %s", cmd_buf);
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

FILE *safe_popen(const char *cmd, pid_t *pid_out) {
    int fd[2];
    if (pipe(fd) < 0) return NULL;
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return NULL;
    }
    if (pid == 0) {
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);

        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        close(fd[1]);

        if (setuid(geteuid()) != 0) perror("setuid failed in safe_popen");
        if (setgid(getegid()) != 0) perror("setgid failed in safe_popen");

        clearenv();
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        char cmd_buf[1024];
        snprintf(cmd_buf, sizeof(cmd_buf), "%s", cmd);
        exec_cmd(cmd_buf);
        _exit(127);
    }
    close(fd[1]);
    *pid_out = pid;
    return fdopen(fd[0], "r");
}

void safe_pclose(FILE *fp, pid_t pid) {
    if (fp) fclose(fp);
    if (pid > 0) {
        int status;
        while (waitpid(pid, &status, 0) == -1) {
            if (errno != EINTR) break;
        }
    }
}
