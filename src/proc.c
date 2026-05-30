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
    char *sudo_user = getenv("SUDO_USER");
    char *sudo_uid_str = getenv("SUDO_UID");
    char *sudo_gid_str = getenv("SUDO_GID");

    if (sudo_user && sudo_uid_str && sudo_gid_str) {
        uid_t uid = (uid_t)strtol(sudo_uid_str, NULL, 10);
        gid_t gid = (gid_t)strtol(sudo_gid_str, NULL, 10);

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
}

int wait_for_process(pid_t pid) {
    int pidfd = my_pidfd_open(pid, 0);
    if (pidfd >= 0) {
        log_debug("Using pidfd to monitor PID %d", pid);
        struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
        while (g_keep_running) {
            int ret = poll(&pfd, 1, 100);
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
