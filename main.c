#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>

enum Mode { MODE_REDIRECT, MODE_TPROXY, MODE_TRACE };

// Global state for cleanup
volatile sig_atomic_t g_keep_running = 1;
int g_cgroup_created = 0;
char g_cgroup_path[256] = {0};
char g_output_chain[128] = {0};
char g_prerouting_chain[128] = {0};
enum Mode g_mode = MODE_REDIRECT;
int g_tproxy_mark = 0;
int g_has_override_dns = 0;

void run_cmd(const char *cmd) {
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Command returned non-zero: %s\n", cmd);
    }
}

void run_cmd_silent(const char *cmd) {
    if (system(cmd)) {}
}

void cleanup(void) {
    static int cleaned_up = 0;
    if (cleaned_up) return;
    cleaned_up = 1;

    // Block signals during cleanup to prevent re-entrancy issues
    sigset_t set;
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, NULL);

    char cmd[512];

    if (g_mode == MODE_REDIRECT) {
        if (g_output_chain[0] != '\0') {
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -D OUTPUT -j %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -F %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -X %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
        }
    } else if (g_mode == MODE_TPROXY) {
        if (g_prerouting_chain[0] != '\0') {
            snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -D PREROUTING -j %s >/dev/null 2>&1", g_prerouting_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -F %s >/dev/null 2>&1", g_prerouting_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -X %s >/dev/null 2>&1", g_prerouting_chain); run_cmd_silent(cmd);
        }
        if (g_output_chain[0] != '\0') {
            snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -D OUTPUT -j %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -F %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -X %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
        }
        if (g_has_override_dns && g_output_chain[0] != '\0') {
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -D OUTPUT -j %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -F %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -X %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
        }
        if (g_tproxy_mark != 0) {
            snprintf(cmd, sizeof(cmd), "ip rule delete fwmark %d table %d >/dev/null 2>&1", g_tproxy_mark, g_tproxy_mark); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "ip route delete local 0.0.0.0/0 dev lo table %d >/dev/null 2>&1", g_tproxy_mark); run_cmd_silent(cmd);
        }
    } else if (g_mode == MODE_TRACE) {
        if (g_output_chain[0] != '\0') {
            snprintf(cmd, sizeof(cmd), "iptables -w -t raw -D OUTPUT -j %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t raw -F %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
            snprintf(cmd, sizeof(cmd), "iptables -w -t raw -X %s >/dev/null 2>&1", g_output_chain); run_cmd_silent(cmd);
        }
    }
    
    if (g_cgroup_created && g_cgroup_path[0] != '\0') {
        rmdir(g_cgroup_path);
        g_cgroup_created = 0;
    }
}

void sig_handler(int sig) {
    (void)sig;
    g_keep_running = 0;
}

int setup_cgroup(pid_t pid, const char *cg_base) {
    snprintf(g_cgroup_path, sizeof(g_cgroup_path), "%s/cproxy-%d", cg_base, pid);
    
    if (mkdir(g_cgroup_path, 0755) != 0) {
        if (errno != EEXIST) {
            perror("Failed to create cgroup directory");
            return -1;
        }
    }
    g_cgroup_created = 1;

    char tasks_file[512];
    snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_cgroup_path);
    FILE *f = fopen(tasks_file, "w");
    if (!f) {
        snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_cgroup_path);
        f = fopen(tasks_file, "w");
        if (!f) {
            perror("Failed to open cgroup.procs or tasks");
            return -1;
        }
    }
    fprintf(f, "%d\n", pid);
    fclose(f);

    char classid_file[512];
    snprintf(classid_file, sizeof(classid_file), "%s/net_cls.classid", g_cgroup_path);
    f = fopen(classid_file, "w");
    if (f) {
        fprintf(f, "%d\n", pid);
        fclose(f);
    }
    return 0;
}

void setup_iptables_redirect(pid_t pid, int port, int redirect_dns, int is_v2, const char* cgroup_path) {
    snprintf(g_output_chain, sizeof(g_output_chain), "cp_rd_out_%d", pid);
    char cmd[1024];

    snprintf(cmd, sizeof(cmd), "iptables -w -t nat -N %s", g_output_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A OUTPUT -j %s", g_output_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p udp -o lo -j RETURN", g_output_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p tcp -o lo -j RETURN", g_output_chain); run_cmd(cmd);

    if (is_v2) {
        snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p tcp -m cgroup --path %s -j REDIRECT --to-ports %d", g_output_chain, cgroup_path, port); run_cmd(cmd);
        if (redirect_dns) {
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p udp -m cgroup --path %s --dport 53 -j REDIRECT --to-ports %d", g_output_chain, cgroup_path, port); run_cmd(cmd);
        }
    } else {
        snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p tcp -m cgroup --cgroup %d -j REDIRECT --to-ports %d", g_output_chain, pid, port); run_cmd(cmd);
        if (redirect_dns) {
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p udp -m cgroup --cgroup %d --dport 53 -j REDIRECT --to-ports %d", g_output_chain, pid, port); run_cmd(cmd);
        }
    }
}

void setup_iptables_tproxy(pid_t pid, int port, const char* override_dns, int is_v2, const char* cgroup_path) {
    g_tproxy_mark = pid;
    snprintf(g_output_chain, sizeof(g_output_chain), "cp_tp_out_%d", pid);
    snprintf(g_prerouting_chain, sizeof(g_prerouting_chain), "cp_tp_pre_%d", pid);
    
    char cmd[1024];
    
    // IP Rules
    snprintf(cmd, sizeof(cmd), "ip rule add fwmark %d table %d", g_tproxy_mark, g_tproxy_mark); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "ip route add local 0.0.0.0/0 dev lo table %d", g_tproxy_mark); run_cmd(cmd);

    // Mangle PREROUTING
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -N %s", g_prerouting_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A PREROUTING -j %s", g_prerouting_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p tcp -o lo -j RETURN", g_prerouting_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p udp -o lo -j RETURN", g_prerouting_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p udp -m mark --mark %d -j TPROXY --on-ip 127.0.0.1 --on-port %d", g_prerouting_chain, g_tproxy_mark, port); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p tcp -m mark --mark %d -j TPROXY --on-ip 127.0.0.1 --on-port %d", g_prerouting_chain, g_tproxy_mark, port); run_cmd(cmd);

    // Mangle OUTPUT
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -N %s", g_output_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A OUTPUT -j %s", g_output_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p tcp -o lo -j RETURN", g_output_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p udp -o lo -j RETURN", g_output_chain); run_cmd(cmd);

    if (override_dns && strlen(override_dns) > 0) {
        g_has_override_dns = 1;
        snprintf(cmd, sizeof(cmd), "iptables -w -t nat -N %s", g_output_chain); run_cmd(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A OUTPUT -j %s", g_output_chain); run_cmd(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p udp -o lo -j RETURN", g_output_chain); run_cmd(cmd);
    }

    if (is_v2) {
        snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p tcp -m cgroup --path %s -j MARK --set-mark %d", g_output_chain, cgroup_path, g_tproxy_mark); run_cmd(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p udp -m cgroup --path %s -j MARK --set-mark %d", g_output_chain, cgroup_path, g_tproxy_mark); run_cmd(cmd);
        if (g_has_override_dns) {
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p udp -m cgroup --path %s --dport 53 -j DNAT --to-destination %s", g_output_chain, cgroup_path, override_dns); run_cmd(cmd);
        }
    } else {
        snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p tcp -m cgroup --cgroup %d -j MARK --set-mark %d", g_output_chain, pid, g_tproxy_mark); run_cmd(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -w -t mangle -A %s -p udp -m cgroup --cgroup %d -j MARK --set-mark %d", g_output_chain, pid, g_tproxy_mark); run_cmd(cmd);
        if (g_has_override_dns) {
            snprintf(cmd, sizeof(cmd), "iptables -w -t nat -A %s -p udp -m cgroup --cgroup %d --dport 53 -j DNAT --to-destination %s", g_output_chain, pid, override_dns); run_cmd(cmd);
        }
    }
}

void setup_iptables_trace(pid_t pid, int is_v2, const char* cgroup_path) {
    snprintf(g_output_chain, sizeof(g_output_chain), "cp_tr_out_%d", pid);
    char cmd[1024];

    snprintf(cmd, sizeof(cmd), "iptables -w -t raw -N %s", g_output_chain); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -w -t raw -A OUTPUT -j %s", g_output_chain); run_cmd(cmd);

    if (is_v2) {
        snprintf(cmd, sizeof(cmd), "iptables -w -t raw -A %s -m cgroup --path %s -p tcp -j LOG", g_output_chain, cgroup_path); run_cmd(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -w -t raw -A %s -m cgroup --path %s -p udp -j LOG", g_output_chain, cgroup_path); run_cmd(cmd);
    } else {
        snprintf(cmd, sizeof(cmd), "iptables -w -t raw -A %s -m cgroup --cgroup %d -p tcp -j LOG", g_output_chain, pid); run_cmd(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -w -t raw -A %s -m cgroup --cgroup %d -p udp -j LOG", g_output_chain, pid); run_cmd(cmd);
    }
}

int is_cgroup_empty(void) {
    if (!g_cgroup_created || g_cgroup_path[0] == '\0') return 1;
    char tasks_file[512];
    snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_cgroup_path);
    FILE *f = fopen(tasks_file, "r");
    if (!f) {
        snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_cgroup_path);
        f = fopen(tasks_file, "r");
        if (!f) return 1; // Can't read, assume empty/gone
    }
    char buf[32];
    int empty = 1;
    if (fgets(buf, sizeof(buf), f) != NULL) {
        empty = 0; // Found at least one PID
    }
    fclose(f);
    return empty;
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "Error: cproxy must be run as root (use sudo)\n");
        return 1;
    }

    int port = 1080;
    int redirect_dns = 0;
    char mode_str[32] = "redirect";
    char override_dns[64] = {0};
    pid_t target_pid = 0;
    
    struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"redirect-dns", no_argument, 0, 'd'},
        {"mode", required_argument, 0, 'm'},
        {"override-dns", required_argument, 0, 'o'},
        {"pid", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:dm:o:i:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'd': redirect_dns = 1; break;
            case 'm': strncpy(mode_str, optarg, sizeof(mode_str)-1); break;
            case 'o': strncpy(override_dns, optarg, sizeof(override_dns)-1); break;
            case 'i': target_pid = atoi(optarg); break;
            default:
                fprintf(stderr, "Usage: %s [--port <port>] [--mode redirect|tproxy|trace] [--pid <pid>] -- <command...>\n", argv[0]);
                return 1;
        }
    }

    if (strcmp(mode_str, "redirect") == 0) g_mode = MODE_REDIRECT;
    else if (strcmp(mode_str, "tproxy") == 0) g_mode = MODE_TPROXY;
    else if (strcmp(mode_str, "trace") == 0) g_mode = MODE_TRACE;
    else {
        fprintf(stderr, "Unknown mode: %s\n", mode_str);
        return 1;
    }

    if (target_pid == 0 && optind >= argc) {
        fprintf(stderr, "Error: No command specified and no --pid provided.\n");
        return 1;
    }

    atexit(cleanup);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    pid_t process_to_proxy = (target_pid > 0) ? target_pid : getpid();
    
    int is_v2 = 0;
    const char *cg_base = "/sys/fs/cgroup/net_cls"; 
    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0) {
        is_v2 = 1;
        cg_base = "/sys/fs/cgroup";
    }

    if (setup_cgroup(process_to_proxy, cg_base) != 0) {
        fprintf(stderr, "Cgroup setup failed.\n");
        return 1;
    }

    char relative_cg_path[256];
    if (is_v2) {
        snprintf(relative_cg_path, sizeof(relative_cg_path), "cproxy-%d", process_to_proxy);
    }

    if (g_mode == MODE_REDIRECT) {
        setup_iptables_redirect(process_to_proxy, port, redirect_dns, is_v2, relative_cg_path);
    } else if (g_mode == MODE_TPROXY) {
        setup_iptables_tproxy(process_to_proxy, port, override_dns, is_v2, relative_cg_path);
    } else if (g_mode == MODE_TRACE) {
        setup_iptables_trace(process_to_proxy, is_v2, relative_cg_path);
    }

    if (target_pid > 0) {
        printf("Proxying existing PID %d in mode '%s'. Press Ctrl+C to stop...\n", target_pid, mode_str);
        while (g_keep_running) {
            sleep(1);
        }
        printf("\nTerminating...\n");
        return 0;
    }

    char *sudo_user = getenv("SUDO_USER");
    char *sudo_uid_str = getenv("SUDO_UID");
    char *sudo_gid_str = getenv("SUDO_GID");

    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("fork failed");
        return 1;
    }

    if (child_pid == 0) {
        // Child
        if (sudo_user && sudo_uid_str && sudo_gid_str) {
            uid_t uid = atoi(sudo_uid_str);
            gid_t gid = atoi(sudo_gid_str);
            
            if (initgroups(sudo_user, gid) != 0) perror("Warning: initgroups failed");
            if (setgid(gid) != 0) perror("setgid failed");
            if (setuid(uid) != 0) perror("setuid failed");

            struct passwd *pw = getpwuid(uid);
            if (pw) {
                setenv("HOME", pw->pw_dir, 1);
                setenv("USER", pw->pw_name, 1);
                setenv("LOGNAME", pw->pw_name, 1);
            }
        }
        
        char env_str[64];
        snprintf(env_str, sizeof(env_str), "cproxy/%d", port);
        setenv("CPROXY_ENV", env_str, 1);

        char **child_argv = &argv[optind];
        execvp(child_argv[0], child_argv);
        perror("execvp failed");
        exit(1);
    } else {
        // Parent
        int status;
        while (waitpid(child_pid, &status, 0) == -1) {
            if (errno == EINTR && g_keep_running == 0) {
                // Sent SIGINT to child as well
                kill(child_pid, SIGINT);
            }
        }
        
        // Wait for all daemonized children in the cgroup to exit
        while (g_keep_running && !is_cgroup_empty()) {
            sleep(1);
        }

        if (WIFEXITED(status)) return WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    }

    return 0;
}
