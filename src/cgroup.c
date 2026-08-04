#include "cproxy.h"
#include <dirent.h>

static int write_cg_file(const char *name, const char *fmt, ...) {
    char path[PATH_MAX + 64];
    snprintf(path, sizeof(path), "%s/%s", g_ctx.cgroup_path, name);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    va_list args;
    va_start(args, fmt);
    int res = vfprintf(f, fmt, args);
    va_end(args);
    fclose(f);
    return (res < 0) ? -1 : 0;
}

static int add_pid_to_cgroup(pid_t pid, const char *path) {
    char file[PATH_MAX + 64];
    snprintf(file, sizeof(file), "%s/cgroup.procs", path);
    FILE *f = fopen(file, "w");
    if (!f) {
        snprintf(file, sizeof(file), "%s/tasks", path);
        f = fopen(file, "w");
    }
    if (!f) return -1;
    fprintf(f, "%d\n", pid);
    fclose(f);
    return 0;
}

static void move_pids_to_parent(const char *cgroup_path, const char *parent_path) {
    char path[PATH_MAX + 64];
    snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_path);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(path, sizeof(path), "%s/tasks", cgroup_path);
        f = fopen(path, "r");
    }

    if (f) {
        pid_t *pids = NULL;
        int count = 0;
        int capacity = 0;
        char buf[32];
        while (fgets(buf, sizeof(buf), f)) {
            pid_t pid = (pid_t)strtol(buf, NULL, 10);
            if (pid > 0) {
                if (count >= capacity) {
                    capacity = capacity == 0 ? 16 : capacity * 2;
                    pid_t *temp = realloc(pids, capacity * sizeof(pid_t));
                    if (!temp) {
                        perror("realloc failed");
                        break;
                    }
                    pids = temp;
                }
                pids[count++] = pid;
            }
        }
        fclose(f);

        for (int i = 0; i < count; i++) {
            add_pid_to_cgroup(pids[i], parent_path);
        }
        free(pids);
    }
}

static void get_current_cgroup_path(char *buf, size_t len) {
    buf[0] = '\0';
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) return;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        // v2: 0::/path
        // v1: 1:net_cls:/path
        char *p = strchr(line, ':');
        if (p && *(p+1) == ':') { // v2
            p += 2;
            char *nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strcmp(p, "/") == 0) buf[0] = '\0';
            else snprintf(buf, len, "%s", p);
            break;
        }
    }
    fclose(f);
}

int init_cgroup_support(void) {
    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0) {
        g_ctx.is_v2 = true;
        snprintf(g_ctx.cg_base, sizeof(g_ctx.cg_base), "/sys/fs/cgroup");
    } else {
        snprintf(g_ctx.cg_base, sizeof(g_ctx.cg_base), "/sys/fs/cgroup/net_cls");
        if (stat(g_ctx.cg_base, &st) != 0) {
            log_error("Cgroup v1 net_cls controller not found at %s", g_ctx.cg_base);
            return -1;
        }
    }
    return 0;
}

int setup_cgroup(pid_t pid) {
    char rel_path[PATH_MAX] = "";
    if (g_ctx.is_v2) {
        get_current_cgroup_path(rel_path, sizeof(rel_path));
    }

    const char *rp = rel_path;
    if (rp[0] == '/' && rp[1] == '\0') rp = "";

    if (snprintf(g_ctx.cgroup_path, sizeof(g_ctx.cgroup_path), "%s%s/cproxy-%d", g_ctx.cg_base, rp, pid) >= (int)sizeof(g_ctx.cgroup_path)) {
        log_error("Cgroup path too long");
        return -1;
    }

    if (g_ctx.verbose) log_info("Creating cgroup: %s", g_ctx.cgroup_path);

    if (g_ctx.dry_run) {
        g_ctx.cgroup_created = true;
        return 0;
    }

    if (mkdir(g_ctx.cgroup_path, 0755) != 0 && errno != EEXIST) {
        perror("mkdir cgroup failed");
        return -1;
    }
    g_ctx.cgroup_created = 1;

    if (add_pid_to_cgroup(pid, g_ctx.cgroup_path) != 0) {
        perror("Failed to add PID to cgroup");
        return -1;
    }

    if (!g_ctx.is_v2) {
        unsigned int classid = (((unsigned int)(pid >> 16) + 1) << 16) | (pid & 0xFFFF);
        if (write_cg_file("net_cls.classid", "0x%08x\n", classid) != 0) {
            log_warn("Failed to set net_cls.classid");
        }
    }
    return 0;
}

int is_cgroup_empty(void) {
    if (!g_ctx.cgroup_created || g_ctx.cgroup_path[0] == '\0') return 1;
    char path[PATH_MAX + 64];
    snprintf(path, sizeof(path), "%s/cgroup.procs", g_ctx.cgroup_path);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(path, sizeof(path), "%s/tasks", g_ctx.cgroup_path);
        f = fopen(path, "r");
    }
    if (!f) return 1;

    char buf[32];
    int empty = 1;
    while (fgets(buf, sizeof(buf), f)) {
        if (strtol(buf, NULL, 10) > 0) {
            empty = 0;
            break;
        }
    }
    fclose(f);
    return empty;
}

void cleanup_cgroup(void) {
    if (!g_ctx.cgroup_created || g_ctx.cgroup_path[0] == '\0') return;

    if (g_ctx.dry_run) {
        g_ctx.cgroup_created = 0;
        return;
    }

    // Move processes to parent
    char parent_path[PATH_MAX];
    snprintf(parent_path, sizeof(parent_path), "%s", g_ctx.cgroup_path);
    char *last_slash = strrchr(parent_path, '/');
    if (last_slash) {
        *last_slash = '\0';

        move_pids_to_parent(g_ctx.cgroup_path, parent_path);
    }

    if (rmdir(g_ctx.cgroup_path) != 0 && errno != ENOENT) {
        if (g_ctx.verbose) log_warn("rmdir '%s' failed: %s", g_ctx.cgroup_path, strerror(errno));
    }
    g_ctx.cgroup_created = 0;
}

static void cleanup_stale_cgroups_recursive(const char *base_path, int depth) {
    if (depth > 5) return; // Prevent too deep recursion or loops

    DIR *dir = opendir(base_path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name) >= (int)sizeof(path)) {
            continue;
        }

        // Determine if it's a directory
        bool is_dir = false;
        if (entry->d_type == DT_DIR) {
            is_dir = true;
        } else if (entry->d_type == DT_UNKNOWN) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                is_dir = true;
            }
        }

        if (strncmp(entry->d_name, "cproxy-", 7) == 0 && is_dir) {
            pid_t pid = (pid_t)strtol(entry->d_name + 7, NULL, 10);
            if (pid > 0 && !is_pid_alive(pid)) {
                // Try to move processes to parent first
                char parent_path[PATH_MAX];
                snprintf(parent_path, sizeof(parent_path), "%s", base_path);

                move_pids_to_parent(path, parent_path);

                if (rmdir(path) == 0) {
                    log_info("Removed stale cgroup: %s", path);
                }
            }
        } else if (is_dir) {
            cleanup_stale_cgroups_recursive(path, depth + 1);
        }
    }
    closedir(dir);
}

void cleanup_stale_cgroups(void) {
    const char *bases[] = {"/sys/fs/cgroup", "/sys/fs/cgroup/net_cls"};
    for (int b = 0; b < 2; b++) {
        cleanup_stale_cgroups_recursive(bases[b], 0);
    }
}
