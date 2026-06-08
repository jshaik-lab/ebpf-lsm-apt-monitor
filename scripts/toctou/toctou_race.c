/*
 * toctou_race.c — Symlink-swap race victim for TOCTOU eBPF micro-benchmark.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

static void pin_cpu0(void)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

static void *attacker_fn(void *arg)
{
    (void)arg;
    pin_cpu0();
    int toggle = 0;
    while (g_running) {
        toggle ^= 1;
        unlink(g_link_path);
        symlink(toggle ? g_shadow_path : g_safe_path, g_link_path);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <workdir> <iterations>\n", argv[0]);
        return 2;
    }

    const char *workdir = argv[1];
    int iterations = atoi(argv[2]);
    if (iterations <= 0)
        return 2;

    snprintf(g_safe_path, sizeof(g_safe_path), "%s/safe.txt", workdir);
    snprintf(g_shadow_path, sizeof(g_shadow_path), "%s/shadow_target", workdir);
    snprintf(g_link_path, sizeof(g_link_path), "%s/race_link", workdir);

    prctl(PR_SET_NAME, "toctou_victim", 0, 0, 0);
    pin_cpu0();

    pthread_t attacker;
    if (pthread_create(&attacker, NULL, attacker_fn, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    for (int i = 0; i < iterations; i++) {
        int fd = open(g_link_path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char buf[16];
            (void)read(fd, buf, sizeof(buf));
            close(fd);
        }
    }

    g_running = 0;
    pthread_join(attacker, NULL);
    return 0;
}
