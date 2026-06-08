// SPDX-License-Identifier: GPL-2.0
// Minimal TOCTOU observer: sys_enter_openat (pre-resolution path) vs lsm/file_open
// (post-resolution path via bpf_d_path).
//
// Compile (on Linux with BTF):
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
//     -I. -c toctou.bpf.c -o toctou.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PATH_LEN 128
#define MARKER   "shadow_target"

char LICENSE[] SEC("license") = "GPL";

struct toctou_stats {
    __u64 opens;
    __u64 lsm_saw_shadow;
    __u64 tp_saw_shadow_path;
    __u64 tp_would_miss_shadow;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct toctou_stats);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, char[PATH_LEN]);
} last_tp_path SEC(".maps");

static __always_inline int path_has_marker(const char *path)
{
    char needle[] = MARKER;
    #pragma unroll
    for (int i = 0; i < PATH_LEN - sizeof(MARKER); i++) {
        if (path[i] == 0)
            break;
        int match = 1;
        #pragma unroll
        for (int j = 0; j < (int)sizeof(MARKER) - 1; j++) {
            if (path[i + j] != needle[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

static __always_inline int pid_is_target(void)
{
    __u32 k = 0;
    __u32 *want = bpf_map_lookup_elem(&target_pid, &k);
    if (!want || *want == 0)
        return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return pid == *want;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (!pid_is_target())
        return 0;

    char path[PATH_LEN] = {};
    bpf_probe_read_user_str(path, sizeof(path), (const void *)ctx->args[1]);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&last_tp_path, &pid, path, BPF_ANY);

    __u32 k = 0;
    struct toctou_stats *s = bpf_map_lookup_elem(&stats, &k);
    if (!s)
        return 0;

    __sync_fetch_and_add(&s->opens, 1);
    if (path_has_marker(path))
        __sync_fetch_and_add(&s->tp_saw_shadow_path, 1);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    if (!pid_is_target())
        return 0;

    char lsm_path[PATH_LEN] = {};
    long ret = bpf_d_path(&file->f_path, lsm_path, sizeof(lsm_path));
    if (ret < 0)
        return 0;

    if (!path_has_marker(lsm_path))
        return 0;

    __u32 k = 0;
    struct toctou_stats *s = bpf_map_lookup_elem(&stats, &k);
    if (!s)
        return 0;

    __sync_fetch_and_add(&s->lsm_saw_shadow, 1);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char *tp = bpf_map_lookup_elem(&last_tp_path, &pid);
    if (tp && !path_has_marker(tp))
        __sync_fetch_and_add(&s->tp_would_miss_shadow, 1);
    return 0;
}
