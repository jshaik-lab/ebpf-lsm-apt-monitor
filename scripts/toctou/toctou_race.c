/*
 * toctou_race.c — Symlink-swap race victim for TOCTOU micro-benchmark.
 *
 * Victim repeatedly open(2)s a symlink while an attacker thread swaps the
 * symlink target between a benign file and a shadow_target marker file.
 *
 * Build: gcc -O2 -pthread -o toctou_race toctou_race.c
 * Usage: toctou_race <workdir> <iterations>
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

static void *attacker_fn(void *arg) {
    (void)arg;
    int toggle = 0;
    while (g_running) {
        toggle ^= 1;
        unlink(g_link_path);
        if (symlink(toggle ? g_shadow_path : g_safe_path, g_link_path) != 0) {
            /* race_link may not exist yet on first swap */
        }
        sched_yield();
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <workdir> <iterations>\n", argv[0]);
        return 2;
    }

    const char *workdir = argv[1];
    int iterations = atoi(argv[2]);
    if (iterations <= 0) {
        fprintf(stderr, "iterations must be > 0\n");
        return 2;
    }

    snprintf(g_safe_path, sizeof(g_safe_path), "%s/safe.txt", workdir);
    snprintf(g_shadow_path, sizeof(g_shadow_path), "%s/shadow_target", workdir);
    snprintf(g_link_path, sizeof(g_link_path), "%s/race_link", workdir);

    prctl(PR_SET_NAME, "toctou_victim", 0, 0, 0);

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
        sched_yield();
    }

    g_running = 0;
    pthread_join(attacker, NULL);
    return 0;
}
