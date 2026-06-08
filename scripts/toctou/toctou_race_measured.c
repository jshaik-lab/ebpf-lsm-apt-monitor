/*
 * toctou_race_measured.c — Self-instrumented symlink race benchmark.
 *
 * For each open(2) of race_link, records:
 *   - tp_path: user-supplied pathname (analogous to sys_enter_openat args[1])
 *   - resolved_path: readlink(/proc/self/fd/N) (post-open kernel resolution)
 *
 * When the attacker wins the race, resolved_path contains shadow_target while
 * tp_path is still race_link — the discrepancy tracepoint-only HIDS miss.
 *
 * Build: gcc -O2 -pthread -o toctou_race_measured toctou_race_measured.c
 * Usage: toctou_race_measured <workdir> <iterations> [out.json]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static volatile int g_running = 1;
static char g_link_path[512];
static char g_safe_path[512];
static char g_shadow_path[512];

struct stats {
    unsigned long opens;
    unsigned long resolved_shadow;
    unsigned long tp_saw_shadow_path;
    unsigned long tp_would_miss_shadow;
};

static void *attacker_fn(void *arg)
{
    (void)arg;
    int toggle = 0;
    while (g_running) {
        toggle ^= 1;
        unlink(g_link_path);
        symlink(toggle ? g_shadow_path : g_safe_path, g_link_path);
        sched_yield();
    }
    return NULL;
}

static int path_has_marker(const char *path, const char *marker)
{
    return path && strstr(path, marker) != NULL;
}

static int write_json(const char *path, struct stats *st, int iterations,
                      const char *workdir)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    double miss = st->opens ? (double)st->tp_would_miss_shadow / st->opens : 0.0;
    double lsm_rate = st->opens ? (double)st->resolved_shadow / st->opens : 0.0;
    fprintf(f,
        "{\n"
        "  \"benchmark\": \"toctou_symlink_race\",\n"
        "  \"method\": \"userspace_open_vs_readlink\",\n"
        "  \"iterations\": %d,\n"
        "  \"workdir\": \"%s\",\n"
        "  \"tracepoint_opens\": %lu,\n"
        "  \"lsm_resolved_shadow\": %lu,\n"
        "  \"tracepoint_saw_shadow_path\": %lu,\n"
        "  \"tracepoint_would_miss_shadow\": %lu,\n"
        "  \"lsm_shadow_resolution_rate\": %.6f,\n"
        "  \"tracepoint_miss_rate\": %.6f,\n"
        "  \"interpretation\": \"tp_path is the pre-resolution openat argument; resolved_path is readlink(/proc/self/fd/N) after open, analogous to lsm/file_open bpf_d_path. tp_would_miss_shadow counts opens where resolution hit shadow_target but tp_path did not.\"\n"
        "}\n",
        iterations, workdir,
        st->opens, st->resolved_shadow, st->tp_saw_shadow_path,
        st->tp_would_miss_shadow, lsm_rate, miss);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <workdir> <iterations> [out.json]\n", argv[0]);
        return 2;
    }

    const char *workdir = argv[1];
    int iterations = atoi(argv[2]);
    const char *out_json = (argc >= 4) ? argv[3] : NULL;
    if (iterations <= 0)
        return 2;

    snprintf(g_safe_path, sizeof(g_safe_path), "%s/safe.txt", workdir);
    snprintf(g_shadow_path, sizeof(g_shadow_path), "%s/shadow_target", workdir);
    snprintf(g_link_path, sizeof(g_link_path), "%s/race_link", workdir);

    prctl(PR_SET_NAME, "toctou_victim", 0, 0, 0);

    pthread_t attacker;
    if (pthread_create(&attacker, NULL, attacker_fn, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    struct stats st = {0};
    const char *marker = "shadow_target";

    for (int i = 0; i < iterations; i++) {
        const char *tp_path = g_link_path;
        int fd = open(tp_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;

        st.opens++;

        char resolved[PATH_MAX] = {};
        char fdlink[64];
        snprintf(fdlink, sizeof(fdlink), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(fdlink, resolved, sizeof(resolved) - 1);
        if (n > 0)
            resolved[n] = '\0';

        if (path_has_marker(resolved, marker))
            st.resolved_shadow++;
        if (path_has_marker(tp_path, marker))
            st.tp_saw_shadow_path++;
        if (path_has_marker(resolved, marker) && !path_has_marker(tp_path, marker))
            st.tp_would_miss_shadow++;

        char buf[16];
        (void)read(fd, buf, sizeof(buf));
        close(fd);
        sched_yield();
    }

    g_running = 0;
    pthread_join(attacker, NULL);

    if (out_json && write_json(out_json, &st, iterations, workdir) != 0) {
        perror("write_json");
        return 1;
    }

    printf("TOCTOU measured (userspace)\n");
    printf("  tracepoint_opens:              %lu\n", st.opens);
    printf("  lsm_resolved_shadow:           %lu\n", st.resolved_shadow);
    printf("  tracepoint_would_miss_shadow:  %lu\n", st.tp_would_miss_shadow);
    if (st.opens)
        printf("  tracepoint_miss_rate:          %.4f\n",
               (double)st.tp_would_miss_shadow / st.opens);
    return 0;
}
