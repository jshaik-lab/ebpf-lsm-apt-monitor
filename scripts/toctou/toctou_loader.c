/*
 * toctou_loader.c — Load TOCTOU eBPF probes, run race victim, emit JSON stats.
 *
 * Build: gcc -O2 -o toctou_loader toctou_loader.c -lbpf -lelf -lz
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct toctou_stats {
    __u64 opens;
    __u64 lsm_saw_shadow;
    __u64 tp_saw_shadow_path;
    __u64 tp_would_miss_shadow;
};

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    if (level > LIBBPF_WARN)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

static int setup_workdir(const char *dir)
{
    char safe[512], shadow[512], link[512];
    snprintf(safe, sizeof(safe), "%s/safe.txt", dir);
    snprintf(shadow, sizeof(shadow), "%s/shadow_target", dir);
    snprintf(link, sizeof(link), "%s/race_link", dir);

    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return -1;

    int sf = open(safe, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (sf < 0)
        return -1;
    const char *msg = "benign\n";
    (void)write(sf, msg, strlen(msg));
    close(sf);

    int sh = open(shadow, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (sh < 0)
        return -1;
    const char *sec = "root:$6$shadow_target$deadbeef\n";
    (void)write(sh, sec, strlen(sec));
    close(sh);

    unlink(link);
    if (symlink(safe, link) != 0)
        return -1;
    return 0;
}

static int write_json(const char *path, struct toctou_stats *st, int iterations,
                      const char *workdir, const char *platform)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;

    double miss_rate = st->opens ? (double)st->tp_would_miss_shadow / st->opens : 0.0;
    double lsm_rate = st->opens ? (double)st->lsm_saw_shadow / st->opens : 0.0;

    fprintf(f,
        "{\n"
        "  \"benchmark\": \"toctou_symlink_race\",\n"
        "  \"iterations\": %d,\n"
        "  \"workdir\": \"%s\",\n"
        "  \"platform\": \"%s\",\n"
        "  \"tracepoint_opens\": %llu,\n"
        "  \"lsm_resolved_shadow\": %llu,\n"
        "  \"tracepoint_saw_shadow_path\": %llu,\n"
        "  \"tracepoint_would_miss_shadow\": %llu,\n"
        "  \"lsm_shadow_resolution_rate\": %.6f,\n"
        "  \"tracepoint_miss_rate\": %.6f,\n"
        "  \"interpretation\": \"When symlink swap wins, LSM bpf_d_path resolves shadow_target while sys_enter_openat records only race_link; tracepoint_would_miss_shadow counts those discrepancy events.\"\n"
        "}\n",
        iterations, workdir, platform,
        (unsigned long long)st->opens,
        (unsigned long long)st->lsm_saw_shadow,
        (unsigned long long)st->tp_saw_shadow_path,
        (unsigned long long)st->tp_would_miss_shadow,
        lsm_rate, miss_rate);
    fclose(f);
    return 0;
}

static void resolve_race_binary(char *race_bin, size_t len, const char *argv0)
{
    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n > 0) {
        self[n] = 0;
        char *slash = strrchr(self, '/');
        if (slash) {
            *slash = 0;
            snprintf(race_bin, len, "%s/toctou_race", self);
            if (access(race_bin, X_OK) == 0)
                return;
        }
    }
    snprintf(race_bin, len, "%s", argv0);
    char *slash = strrchr(race_bin, '/');
    if (slash) {
        *slash = 0;
        snprintf(race_bin, len, "%s/toctou_race", race_bin);
    } else {
        snprintf(race_bin, len, "./toctou_race");
    }
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <toctou.bpf.o> <iterations> <out.json> [workdir]\n", argv[0]);
        return 2;
    }

    const char *bpf_obj = argv[1];
    int iterations = atoi(argv[2]);
    const char *out_json = argv[3];
    char workdir_buf[512];
    const char *workdir = (argc >= 5) ? argv[4] : "/tmp/sentinel_toctou";
    if (argc < 5) {
        snprintf(workdir_buf, sizeof(workdir_buf), "%s_%d", workdir, getpid());
        workdir = workdir_buf;
    }

    if (iterations <= 0) {
        fprintf(stderr, "iterations must be > 0\n");
        return 2;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: must run as root for BPF LSM hooks\n");
        return 1;
    }

    libbpf_set_print(libbpf_print);

    if (setup_workdir(workdir) != 0) {
        perror("setup_workdir");
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(bpf_obj, NULL);
    if (!obj) {
        fprintf(stderr, "failed to open %s\n", bpf_obj);
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog_tp = bpf_object__find_program_by_name(obj, "tp_openat");
    struct bpf_program *prog_lsm = bpf_object__find_program_by_name(obj, "lsm_file_open");
    if (!prog_tp || !prog_lsm) {
        fprintf(stderr, "BPF programs not found in object\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_link *link_tp = bpf_program__attach(prog_tp);
    struct bpf_link *link_lsm = bpf_program__attach(prog_lsm);
    if (!link_tp || !link_lsm) {
        fprintf(stderr, "failed to attach BPF programs (need Linux >=5.7, CONFIG_BPF_LSM)\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *map_stats = bpf_object__find_map_by_name(obj, "stats");
    struct bpf_map *map_pid = bpf_object__find_map_by_name(obj, "target_pid");
    if (!map_stats || !map_pid) {
        fprintf(stderr, "BPF maps not found\n");
        bpf_object__close(obj);
        return 1;
    }

    char race_bin[PATH_MAX];
    resolve_race_binary(race_bin, sizeof(race_bin), argv[0]);

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        bpf_object__close(obj);
        return 1;
    }

    if (child == 0) {
        char iters[32];
        snprintf(iters, sizeof(iters), "%d", iterations);
        execl(race_bin, race_bin, workdir, iters, (char *)NULL);
        perror("execl toctou_race");
        _exit(127);
    }

    __u32 pid = (__u32)child;
    __u32 k = 0;
    bpf_map__update_elem(map_pid, &k, sizeof(k), &pid, sizeof(pid), BPF_ANY);

    int status = 0;
    waitpid(child, &status, 0);

    struct toctou_stats st = {};
    bpf_map__lookup_elem(map_stats, &k, sizeof(k), &st, sizeof(st), BPF_ANY);

    char platform[256];
    const char *plat = getenv("SENTINEL_EVAL_PLATFORM");
    snprintf(platform, sizeof(platform), "%s", plat ? plat : "Linux auto");

    if (write_json(out_json, &st, iterations, workdir, platform) != 0) {
        perror("write_json");
        bpf_object__close(obj);
        return 1;
    }

    printf("TOCTOU benchmark complete\n");
    printf("  tracepoint_opens:              %llu\n", (unsigned long long)st.opens);
    printf("  lsm_resolved_shadow:           %llu\n", (unsigned long long)st.lsm_saw_shadow);
    printf("  tracepoint_would_miss_shadow:  %llu\n", (unsigned long long)st.tp_would_miss_shadow);
    if (st.opens)
        printf("  tracepoint_miss_rate:          %.4f\n",
               (double)st.tp_would_miss_shadow / st.opens);

    bpf_link__destroy(link_tp);
    bpf_link__destroy(link_lsm);
    bpf_object__close(obj);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}
