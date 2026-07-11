#define _GNU_SOURCE
#ifndef CPROXY_H
#define CPROXY_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>

#define CPROXY_VERSION "1.2.2"

enum Mode { MODE_REDIRECT, MODE_TPROXY, MODE_TRACE };

typedef struct {
    char addr[64];
    bool is_v6;
} BypassRule;

typedef struct {
    int port;
    int dns_port;
    bool redirect_dns;
    enum Mode mode;
    char override_dns[64];
    char *bypass_str;
    BypassRule *bypass_rules;
    int bypass_count;
    pid_t target_pid;
    bool verbose;
    bool dry_run;
    bool is_v2;
    char cg_base[PATH_MAX];
    char cgroup_path[PATH_MAX];
    int tproxy_mark;
    bool has_override_dns;
    bool cgroup_created;
    bool clean_stale;
} Context;

extern Context g_ctx;
extern volatile sig_atomic_t g_keep_running;

// Util / Cmd
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} LogLevel;

void log_msg(LogLevel level, const char *fmt, ...);
#define log_debug(...) log_msg(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define log_info(...)  log_msg(LOG_LEVEL_INFO, __VA_ARGS__)
#define log_warn(...)  log_msg(LOG_LEVEL_WARN, __VA_ARGS__)
#define log_error(...) log_msg(LOG_LEVEL_ERROR, __VA_ARGS__)

double get_time_ms(void);
int run_cmd_v(const char *fmt, va_list args, int silent);
int run_cmd(const char *fmt, ...);
int run_cmd_silent(const char *fmt, ...);
FILE *safe_popen(const char *cmd, pid_t *pid_out);
void safe_pclose(FILE *fp, pid_t pid);
int is_valid_ipv4(const char *ip);
int is_valid_ipv6(const char *ip);
int is_valid_bypass_str(const char* str);
int is_pid_alive(pid_t pid);
int parse_bypass_rules(Context *ctx);
int check_dependencies(void);

// Cgroup
int init_cgroup_support(void);
int setup_cgroup(pid_t pid);
int is_cgroup_empty(void);
void cleanup_cgroup(void);
void cleanup_stale_cgroups(void);

// Iptables
int init_chain(const char *table, const char *chain, const char *parent, const char *iptables_cmd, const char *match);
int apply_bypass_rules(const char* chain, const char* table, const char* iptables_cmd);
int setup_iptables(pid_t pid);
void cleanup_iptables(void);
void cleanup_stale_iptables(void);

// Process / Args
int parse_args(Context *ctx, int argc, char *argv[]);
int wait_for_process(pid_t pid);
void drop_privileges(void);
int check_process_ownership(pid_t pid);

// Cleanup
void cleanup(void);
void do_clean_stale(void);

#endif
