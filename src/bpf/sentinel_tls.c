// SPDX-License-Identifier: GPL-2.0
// sentinel_tls.c — SENTINEL SSL/TLS Uprobe Layer
//
// Attaches uprobes to libssl's SSL_read and SSL_write to intercept
// encrypted AI-agent traffic (LLM API calls) post-TLS decryption.
// Enables prompt-injection APT detection without MITM proxies or CA certs.
//
// Usage: sentinel attach-tls --pid <agent-pid> --lib /path/to/libssl.so.3
//
// Kernel requirement: Linux >= 5.8 (uprobes + BPF_MAP_TYPE_RINGBUF)
// Compile: clang -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf \
//          -c sentinel_tls.c -o sentinel_tls.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//── Constants ─────────────────────────────────────────────────────────────────

#define TLS_BUF_LEN    512    // max plaintext bytes captured per call
#define MAX_SESSIONS  1024    // max concurrent SSL sessions tracked
#define TASK_COMM_LEN   16

//── TLS event structure ───────────────────────────────────────────────────────

struct tls_event_t {
    __u64  ts_ns;
    __u32  pid;
    __u32  uid;
    __u8   direction;    // 0 = SSL_read (inbound),  1 = SSL_write (outbound)
    __u8   truncated;    // 1 if payload was capped at TLS_BUF_LEN
    __u16  data_len;     // actual plaintext length returned by OpenSSL
    char   comm[TASK_COMM_LEN];
    char   payload[TLS_BUF_LEN];
} __attribute__((packed));

//── Stash map: SSL_read entry args ────────────────────────────────────────────
// Stores {buf pointer, max bytes} between uprobe entry and uretprobe return.
// Keyed by thread ID so concurrent calls don't collide.

struct ssl_args_t {
    __u64 buf;   // user-space VA of plaintext output buffer
    __u64 num;   // max bytes requested (SSL_read arg3)
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key,   __u32);   // tid
    __type(value, struct ssl_args_t);
} ssl_args_map SEC(".maps");

//── Ring buffer: TLS events to user-space ─────────────────────────────────────

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);   // 8 MB
} tls_events SEC(".maps");

//── SSL_read uprobe — entry ───────────────────────────────────────────────────
// Signature: int SSL_read(SSL *ssl, void *buf, int num);
// We stash buf and num; actual bytes are read at uretprobe return.

SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_args_t args = {
        .buf = (unsigned long)PT_REGS_PARM2(ctx),
        .num = (unsigned long)PT_REGS_PARM3(ctx),
    };
    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);
    return 0;
}

//── SSL_read uretprobe — return ───────────────────────────────────────────────
// Return value (rax) is the number of bytes actually decrypted into buf.
// Negative means error; zero means connection closed — skip both.

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 pid = bpf_get_current_pid_tgid() >> 32;

    struct ssl_args_t *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        return 0;
    }

    struct tls_event_t *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        return 0;
    }

    __u32 cap = ((__u32)ret < TLS_BUF_LEN) ? (__u32)ret : TLS_BUF_LEN;

    e->ts_ns     = bpf_ktime_get_ns();
    e->pid       = (__u32)pid;
    e->uid       = bpf_get_current_uid_gid() >> 32;
    e->direction = 0;   // inbound
    e->data_len  = (__u16)ret;
    e->truncated = ((__u32)ret > TLS_BUF_LEN) ? 1 : 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user(e->payload, cap, (void *)args->buf);

    bpf_map_delete_elem(&ssl_args_map, &tid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── SSL_write uprobe — entry ──────────────────────────────────────────────────
// Signature: int SSL_write(SSL *ssl, const void *buf, int num);
// Payload is available at entry (buf is the plaintext to encrypt+send).

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int  num        = (int)PT_REGS_PARM3(ctx);
    if (num <= 0) return 0;

    struct tls_event_t *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
    if (!e) return 0;

    __u32 cap = ((__u32)num < TLS_BUF_LEN) ? (__u32)num : TLS_BUF_LEN;

    e->ts_ns     = bpf_ktime_get_ns();
    e->pid       = (__u32)pid;
    e->uid       = bpf_get_current_uid_gid() >> 32;
    e->direction = 1;   // outbound
    e->data_len  = (__u16)num;
    e->truncated = ((__u32)num > TLS_BUF_LEN) ? 1 : 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user(e->payload, cap, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── SSL_write uretprobe — return ──────────────────────────────────────────────
// Payload was captured at entry; here we only note partial-write failures.

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    // Negative return indicates a TLS error (alert sent to peer).
    // Future extension: update per-session byte counters in a perf map.
    (void)ret;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
