#include "cproxy.h"
#include <sys/syscall.h>
#include <poll.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

static int my_pidfd_open(pid_t pid, unsigned int flags) {
    return syscall(__NR_pidfd_open, pid, flags);
}

void drop_privileges(void) {
    uid_t ruid = getuid();
    uid_t euid = geteuid();
    gid_t rgid = getgid();

    char *sudo_user = getenv("SUDO_USER");
    char *sudo_uid_str = getenv("SUDO_UID");
    char *sudo_gid_str = getenv("SUDO_GID");

    uid_t target_uid = 0;
    gid_t target_gid = 0;
    struct passwd *pw = NULL;

    if (g_ctx.run_as_user[0] != '\0') {
        if (ruid != 0) {
            fprintf(stderr, "FATAL: --user cannot be used when running cproxy as a setuid binary.\n");
            _exit(1);
        }
        pw = getpwnam(g_ctx.run_as_user);
        if (!pw) {
            fprintf(stderr, "Error: User '%s' not found.\n", g_ctx.run_as_user);
            _exit(1);
        }
        target_uid = pw->pw_uid;
        target_gid = pw->pw_gid;
    } else if (sudo_user && sudo_uid_str && sudo_gid_str) {
        target_uid = (uid_t)strtol(sudo_uid_str, NULL, 10);
        target_gid = (gid_t)strtol(sudo_gid_str, NULL, 10);
        pw = getpwuid(target_uid);
    } else if (ruid != 0 || euid == 0) {
        // Not run via sudo, but might be setuid root.
        // If ruid != 0, an unprivileged user ran the binary.
        if (ruid != 0) {
            target_uid = ruid;
            target_gid = rgid;
            pw = getpwuid(target_uid);
        }
    }

    if (target_uid != 0 || pw != NULL) {
        if (pw) {
            if (initgroups(pw->pw_name, target_gid) != 0) {
                perror("initgroups failed");
                _exit(1);
            }
        } else {
            if (setgroups(1, &target_gid) != 0) {
                perror("setgroups failed");
                _exit(1);
            }
        }

        if (setgid(target_gid) != 0) {
            perror("setgid failed");
            _exit(1);
        }
        if (setuid(target_uid) != 0) {
            perror("setuid failed");
            _exit(1);
        }

        if (pw) {
            setenv("HOME", pw->pw_dir, 1);
            setenv("USER", pw->pw_name, 1);
            setenv("LOGNAME", pw->pw_name, 1);
            if (pw->pw_shell && pw->pw_shell[0]) {
                setenv("SHELL", pw->pw_shell, 1);
            }

            // Restore XDG_RUNTIME_DIR which is often stripped by sudo
            // and required by many user-space Linux programs (DBus, PulseAudio, etc.)
            char xdg_dir[64];
            snprintf(xdg_dir, sizeof(xdg_dir), "/run/user/%u", target_uid);
            setenv("XDG_RUNTIME_DIR", xdg_dir, 0); // 0 = don't overwrite if user passed it via sudo -E
        }

        // Unset SUDO_* variables so the child process doesn't behave unexpectedly
        unsetenv("SUDO_USER");
        unsetenv("SUDO_UID");
        unsetenv("SUDO_GID");
        unsetenv("SUDO_COMMAND");
    }
}

int wait_for_process(pid_t pid) {
    int pidfd = my_pidfd_open(pid, 0);
    if (pidfd >= 0) {
        log_debug("Using pidfd to monitor PID %d", pid);
        struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
        while (g_keep_running) {
            int ret = poll(&pfd, 1, -1);
            if (ret > 0) {
                close(pidfd);
                return 0; // Exited
            }
            if (ret < 0 && errno != EINTR) {
                log_error("poll pidfd failed");
                break;
            }
        }
        close(pidfd);
    } else {
        log_debug("Falling back to kill(0) polling for PID %d", pid);
        while (g_keep_running) {
            if (kill(pid, 0) == -1 && errno == ESRCH) break;
            usleep(100000);
        }
    }
    return 0;
}

int check_process_ownership(pid_t pid) {
    if (getuid() == 0) return 0; // root can attach to anything

    char path[256];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    struct stat st;
    if (stat(path, &st) != 0) {
        log_error("Could not access PID %d", pid);
        return -1;
    }

    if (st.st_uid != getuid()) {
        log_error("Permission denied: You do not own PID %d", pid);
        return -1;
    }
    return 0;
}
