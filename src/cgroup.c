#include "cproxy.h"

int setup_cgroup(pid_t pid) {
    if (snprintf(g_ctx.cgroup_path, sizeof(g_ctx.cgroup_path), "%s/cproxy-%d", g_ctx.cg_base, pid) >= (int)sizeof(g_ctx.cgroup_path)) {
        fprintf(stderr, "Error: Cgroup path too long\n");
        return -1;
    }

    if (g_ctx.dry_run) {
        printf("[DEBUG] Would create cgroup: %s\n", g_ctx.cgroup_path);
        g_ctx.cgroup_created = 1;
        return 0;
    }

    if (mkdir(g_ctx.cgroup_path, 0755) != 0) {
        if (errno != EEXIST) {
            perror("Failed to create cgroup directory");
            return -1;
        }
    }
    g_ctx.cgroup_created = 1;

    char tasks_file[PATH_MAX + 64];
    snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_ctx.cgroup_path);
    FILE *f = fopen(tasks_file, "w");
    if (!f) {
        snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_ctx.cgroup_path);
        f = fopen(tasks_file, "w");
        if (!f) {
            perror("Failed to open cgroup.procs or tasks");
            return -1;
        }
    }
    fprintf(f, "%d\n", pid);
    fclose(f);

    if (!g_ctx.is_v2) {
        char classid_file[PATH_MAX + 64];
        snprintf(classid_file, sizeof(classid_file), "%s/net_cls.classid", g_ctx.cgroup_path);
        f = fopen(classid_file, "w");
        if (f) {
            fprintf(f, "0x%08x\n", (1 << 16) | (pid & 0xFFFF));
            fclose(f);
        }
    }
    return 0;
}

int is_cgroup_empty(void) {
    if (!g_ctx.cgroup_created || g_ctx.cgroup_path[0] == '\0') return 1;
    char tasks_file[PATH_MAX + 64];
    snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_ctx.cgroup_path);
    FILE *f = fopen(tasks_file, "r");
    if (!f) {
        snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_ctx.cgroup_path);
        f = fopen(tasks_file, "r");
        if (!f) return 1;
    }
    char buf[32];
    int empty = 1;
    while (fgets(buf, sizeof(buf), f) != NULL) {
        if (atoi(buf) > 0) {
            empty = 0;
            break;
        }
    }
    fclose(f);
    return empty;
}

void cleanup_cgroup(void) {
    if (g_ctx.cgroup_created && g_ctx.cgroup_path[0] != '\0') {
        if (g_ctx.dry_run) {
            printf("[DEBUG] Would cleanup cgroup: %s\n", g_ctx.cgroup_path);
            g_ctx.cgroup_created = 0;
            return;
        }
        char parent_tasks_file[PATH_MAX + 64];
        char cg_base_path[PATH_MAX];
        snprintf(cg_base_path, sizeof(cg_base_path), "%s", g_ctx.cgroup_path);
        char *last_slash = strrchr(cg_base_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(parent_tasks_file, sizeof(parent_tasks_file), "%s/cgroup.procs", cg_base_path);
            FILE *f_parent = fopen(parent_tasks_file, "w");
            if (!f_parent) {
                snprintf(parent_tasks_file, sizeof(parent_tasks_file), "%s/tasks", cg_base_path);
                f_parent = fopen(parent_tasks_file, "w");
            }
            if (f_parent) {
                char tasks_file[PATH_MAX + 64];
                snprintf(tasks_file, sizeof(tasks_file), "%s/cgroup.procs", g_ctx.cgroup_path);
                FILE *f = fopen(tasks_file, "r");
                if (!f) {
                    snprintf(tasks_file, sizeof(tasks_file), "%s/tasks", g_ctx.cgroup_path);
                    f = fopen(tasks_file, "r");
                }
                if (f) {
                    char buf[32];
                    while (fgets(buf, sizeof(buf), f) != NULL) {
                        int pid = atoi(buf);
                        if (pid > 0) {
                            fprintf(f_parent, "%d\n", pid);
                            fflush(f_parent);
                        }
                    }
                    fclose(f);
                }
                fclose(f_parent);
            }
        }
        if (rmdir(g_ctx.cgroup_path) != 0 && errno != ENOENT) {
            if (g_ctx.verbose) perror("rmdir cgroup failed");
        }
        g_ctx.cgroup_created = 0;
    }
}
