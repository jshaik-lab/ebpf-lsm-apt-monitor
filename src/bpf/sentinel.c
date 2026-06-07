// SPDX-License-Identifier: GPL-2.0
// sentinel.c — SENTINEL eBPF Kernel Component
//
// Attaches to BTF-enabled tracepoints and LSM hooks for execve, openat,
// connect, setuid, ptrace, and prctl.  Emits typed events via a lock-free
// ring buffer (BPF_MAP_TYPE_RINGBUF) and maintains:
//   - Per-PID sliding-window entropy histograms (LRU_PERCPU_HASH)
//   - Process lineage tracking (PERCPU_HASH: pid → comm + ppid + exec_path)
//   - Comm-name change detection via prctl(PR_SET_NAME) hook
//
// ARM64 note: on AArch64, syscall arguments arrive in registers x0–x7.
// The BTF-enabled tracepoint ctx->args[] array maps directly to x0–x7 as
// read by the kernel's ptrace_get_syscall_args() path, giving us 1:1 register
// access without any additional stack walking.
//
// Kernel requirement: Linux >= 5.8 (BPF_MAP_TYPE_RINGBUF, lsm/ hooks)
// Compile (ARM64):
//   clang -O2 -target bpf -D__TARGET_ARCH_arm64 \
//         -I/usr/include/bpf -I/usr/include/linux \
//         -g -c sentinel.c -o sentinel.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//── Constants ─────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN    16
#define RESOURCE_LEN    128
#define EXEC_PATH_LEN    64
#define ENTROPY_WINDOW   64    // sliding window width (events per PID)
#define SC_TYPES         16    // number of tracked syscall categories
#define MAX_PIDS      65536
#define MAX_ENFORCED   4096

// prctl option for comm rename — must match linux/prctl.h
#define PR_SET_NAME   15

// Syscall type identifiers (must match Python enum SyscallType)
#define SC_EXEC     0
#define SC_FILE_R   1
#define SC_FILE_W   2
#define SC_NET_CON  3
#define SC_NET_LIS  4
#define SC_FORK     5
#define SC_CLONE    6
#define SC_SETUID   7
#define SC_MMAP     8
#define SC_PTRACE   9
#define SC_PRCTL   10   // comm masquerading (PR_SET_NAME)
#define SC_OTHER   15

// Enforcement actions written by user space into enforce_map
#define ENF_NONE      0
#define ENF_SIGSTOP   1
#define ENF_SIGKILL   2
#define ENF_QUARANTINE 3

//── Event structure (shared with user space via ring buffer) ──────────────────
//
// ARM64 register mapping for execve (AX-1 in SENTINEL paper):
//   x0 = filename ptr  → resource field
//   x1 = argv ptr      → not captured (argv expansion in user space)
//   x2 = envp ptr      → not captured
//   arm64_regs[0..2]   → raw register values for forensic use

struct event_t {
    __u64  ts_ns;
    __u32  pid;
    __u32  ppid;
    __u32  uid;
    __u32  gid;
    __u8   sc_type;
    __u8   flags;         // O_WRONLY, O_RDONLY etc. for file events
    __u16  net_port;      // destination port for NET events
    __u32  net_ip4;       // destination IPv4 for NET events
    // ARM64 register capture: x0–x2 for execve, x0–x1 for openat
    // Enables the LTL guardian to verify syscall args against user-space claims.
    __u64  arm64_regs[3]; // raw x0, x1, x2 from tracepoint ctx->args[]
    char   comm[TASK_COMM_LEN];
    char   resource[RESOURCE_LEN];
    // original_comm: filled on prctl(PR_SET_NAME) events to capture the name
    // that was SET (resource) and the name BEFORE the change (original_comm).
    char   original_comm[TASK_COMM_LEN];
    // PCABP: user-space instruction pointer captured via bpf_get_stack().
    // Top-of-stack return address identifies the CALL SITE that invoked the syscall.
    // 0 = stack walk failed.  Non-zero = feed to ValidCallSiteMap + behavioral encoder.
    __u64  user_ip;
} __attribute__((packed));

//── Entropy histogram (per PID, per syscall category) ─────────────────────────

struct entropy_hist_t {
    __u32  counts[SC_TYPES];
    __u32  total;
    __u32  window_pos;   // ring index within sliding window
    __u8   window[ENTROPY_WINDOW];  // recent SC_TYPE values
};

//── Process lineage record ────────────────────────────────────────────────────
// Tracks PID → (ppid, original_comm, exec_path, prctl_rename_count).
// Used by the LTL Symbolic Guardian to detect comm masquerading:
// if prctl_rename_count > 0, the process changed its visible name — a strong
// indicator of defense evasion (MITRE T1036.004).
//
// Uses BPF_MAP_TYPE_PERCPU_HASH for lock-free concurrent updates on SMP.
// Each CPU maintains its own copy; user space reads all CPUs and merges.

struct lineage_t {
    __u32  ppid;
    __u32  prctl_rename_count;   // number of PR_SET_NAME calls
    char   original_comm[TASK_COMM_LEN];  // comm at first exec
    char   current_comm[TASK_COMM_LEN];   // current (possibly renamed) comm
    char   exec_path[EXEC_PATH_LEN];      // path of first execve
    __u64  first_seen_ns;
    __u64  last_prctl_ns;        // timestamp of most recent name change
};

//── Maps ──────────────────────────────────────────────────────────────────────

// Primary telemetry ring buffer (16 MB)
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Per-PID entropy histograms (LRU, per-CPU for lock-free updates)
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key,  __u32);
    __type(value, struct entropy_hist_t);
} entropy_map SEC(".maps");

// Process lineage: pid → lineage_t (per-CPU, no lock contention on SMP)
// Survives across execve() — kernel replaces comm but we track the original.
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key,  __u32);
    __type(value, struct lineage_t);
} lineage_map SEC(".maps");

// Enforcement decisions written by user-space CWAE engine
// key=PID, value=enforcement action (ENF_*)
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENFORCED);
    __type(key,  __u32);
    __type(value, __u8);
} enforce_map SEC(".maps");

// Bloom filter for novel process-resource pairs (secondary entropy-gate bypass)
struct {
    __uint(type,        BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, 1 << 20);
    __type(value, __u64);
} seen_pr_pairs SEC(".maps");

// XDP quarantine: network namespace IDs of quarantined processes
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENFORCED);
    __type(key,  __u64);   // netns cookie
    __type(value, __u8);
} xdp_quarantine_map SEC(".maps");

//── Helpers ───────────────────────────────────────────────────────────────────

static __always_inline void _update_entropy_map(
        __u32 pid, __u8 sc_type) {
    struct entropy_hist_t *h = bpf_map_lookup_elem(&entropy_map, &pid);
    if (!h) {
        struct entropy_hist_t init = {};
        bpf_map_update_elem(&entropy_map, &pid, &init, BPF_ANY);
        h = bpf_map_lookup_elem(&entropy_map, &pid);
        if (!h) return;
    }

    // Subtract evicted element from histogram
    __u32 pos = h->window_pos & (ENTROPY_WINDOW - 1);
    __u8 evicted = h->window[pos];
    if (h->total >= ENTROPY_WINDOW && evicted < SC_TYPES)
        h->counts[evicted]--;

    // Add new element
    h->window[pos]      = sc_type;
    h->window_pos       = (pos + 1) & (ENTROPY_WINDOW - 1);
    if (sc_type < SC_TYPES)
        h->counts[sc_type]++;
    if (h->total < ENTROPY_WINDOW)
        h->total++;
}

static __always_inline int _check_enforce(__u32 pid) {
    __u8 *action = bpf_map_lookup_elem(&enforce_map, &pid);
    if (!action) return ENF_NONE;
    return (int)*action;
}

static __always_inline __u32 _get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    __u32 ppid = 0;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&ppid,   sizeof(ppid),   &parent->tgid);
    return ppid;
}

// Record or update the lineage entry for this PID.
// Called on every execve so we capture the original comm before any prctl rename.
static __always_inline void _update_lineage(
        __u32 pid, __u32 ppid, const char *comm_buf, const char *exec_path) {
    struct lineage_t *lin = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!lin) {
        struct lineage_t init = {};
        init.ppid            = ppid;
        init.prctl_rename_count = 0;
        init.first_seen_ns   = bpf_ktime_get_ns();
        // Store original comm and exec_path at first execve
        __builtin_memcpy(init.original_comm, comm_buf, TASK_COMM_LEN);
        __builtin_memcpy(init.current_comm,  comm_buf, TASK_COMM_LEN);
        if (exec_path)
            bpf_probe_read_user_str(init.exec_path, sizeof(init.exec_path),
                                    (const void *)exec_path);
        bpf_map_update_elem(&lineage_map, &pid, &init, BPF_ANY);
    }
    // (If entry exists, we don't overwrite original_comm — preserving ancestry)
}

//── Tracepoint: sys_enter_execve ──────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;

    // Enforce any pending action before the new program launches
    int action = _check_enforce(pid);
    if (action == ENF_SIGKILL)
        bpf_send_signal(9);
    else if (action == ENF_SIGSTOP)
        bpf_send_signal(19);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns   = bpf_ktime_get_ns();
    e->pid     = pid;
    e->ppid    = _get_ppid();
    e->uid     = bpf_get_current_uid_gid() >> 32;
    e->gid     = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type = SC_EXEC;
    e->flags   = 0;
    e->net_port = 0;
    e->net_ip4  = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->resource, sizeof(e->resource),
                            (const void *)ctx->args[0]);

    // ARM64: x0=filename, x1=argv, x2=envp — capture raw register values
    e->arm64_regs[0] = ctx->args[0];  // filename ptr (x0)
    e->arm64_regs[1] = ctx->args[1];  // argv ptr    (x1)
    e->arm64_regs[2] = ctx->args[2];  // envp ptr    (x2)

    __builtin_memset(e->original_comm, 0, sizeof(e->original_comm));

    _update_lineage(pid, e->ppid, e->comm, (const char *)ctx->args[0]);
    _update_entropy_map(pid, SC_EXEC);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── Tracepoint: sys_enter_openat ──────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    int flags      = (int)ctx->args[2];

    __u8 sc_type   = (flags & 1) ? SC_FILE_W : SC_FILE_R;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns   = bpf_ktime_get_ns();
    e->pid     = pid;
    e->ppid    = _get_ppid();
    e->uid     = bpf_get_current_uid_gid() >> 32;
    e->gid     = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type = sc_type;
    e->flags   = (__u8)(flags & 0xFF);
    e->net_port = 0;
    e->net_ip4  = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    // args[1] = pathname pointer
    bpf_probe_read_user_str(e->resource, sizeof(e->resource),
                            (const void *)ctx->args[1]);

    _update_entropy_map(pid, sc_type);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── PCABP: user-space instruction pointer capture ─────────────────────────────
//
// bpf_get_stack with BPF_F_USER_STACK returns the user-space call stack.
// user_stack[0] is the return address from the CALL instruction — i.e., the
// instruction immediately after the call site that invoked the syscall.
// This tells us WHERE in the process address space the syscall originated:
//   - If within [binary_base, binary_base + text_size] → legitimate in-binary call
//   - If in heap / mmap / stack region → injected shellcode (PCABP violation)

static __always_inline __u64 _capture_user_ip(void *ctx)
{
    __u64 user_stack[1] = {};
    long ret = bpf_get_stack(ctx, user_stack, sizeof(user_stack),
                             BPF_F_USER_STACK);
    if (ret == sizeof(__u64))
        return user_stack[0];
    return 0ULL;
}

//── Tracepoint: sys_enter_connect (IPv4 TCP) ──────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;

    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa),
                        (const void *)ctx->args[1]);

    // Only trace IPv4 TCP connections
    if (sa.sin_family != AF_INET) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns    = bpf_ktime_get_ns();
    e->pid      = pid;
    e->ppid     = _get_ppid();
    e->uid      = bpf_get_current_uid_gid() >> 32;
    e->gid      = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type  = SC_NET_CON;
    e->flags    = 0;
    e->net_port = bpf_ntohs(sa.sin_port);
    e->net_ip4  = sa.sin_addr.s_addr;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    // Build resource string: ip4:port
    __builtin_snprintf(e->resource, sizeof(e->resource),
                       "%u.%u.%u.%u:%u",
                       (sa.sin_addr.s_addr >>  0) & 0xFF,
                       (sa.sin_addr.s_addr >>  8) & 0xFF,
                       (sa.sin_addr.s_addr >> 16) & 0xFF,
                       (sa.sin_addr.s_addr >> 24) & 0xFF,
                       bpf_ntohs(sa.sin_port));

    e->user_ip = _capture_user_ip(ctx);
    _update_entropy_map(pid, SC_NET_CON);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── Tracepoint: sys_enter_write (PCABP write-from-heap detection) ─────────────
//
// Heap-injected shellcode typically issues write() to exfiltrate data or to
// write a staged payload to disk.  By capturing user_ip we can distinguish:
//   write() from nginx .text (serving a response) vs
//   write() from heap (shellcode writing /tmp/implant)

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;

    // Filter: only trace writes to low-numbered fds (stdout/stderr/socket)
    // and fds that might be sockets or sensitive files. Skip high-fd noise.
    int fd = (int)ctx->args[0];
    if (fd < 0 || fd > 1024) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns   = bpf_ktime_get_ns();
    e->pid     = pid;
    e->ppid    = _get_ppid();
    e->uid     = bpf_get_current_uid_gid() >> 32;
    e->gid     = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type = SC_FILE_W;
    e->flags   = (fd <= 2) ? 1 : 0;   // flag stdio writes
    e->user_ip = _capture_user_ip(ctx);

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_snprintf(e->resource, sizeof(e->resource), "fd:%d", fd);

    _update_entropy_map(pid, SC_FILE_W);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── Tracepoint: setuid (privilege escalation detection) ───────────────────────

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    __u32 target_uid = (__u32)ctx->args[0];

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns   = bpf_ktime_get_ns();
    e->pid     = pid;
    e->ppid    = _get_ppid();
    e->uid     = bpf_get_current_uid_gid() >> 32;
    e->gid     = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type = SC_SETUID;
    e->flags   = (target_uid == 0) ? 0x01 : 0x00;  // flag root escalation
    e->net_port = 0;
    e->net_ip4  = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_snprintf(e->resource, sizeof(e->resource),
                       "uid=%u->%u", e->uid, target_uid);

    _update_entropy_map(pid, SC_SETUID);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── Tracepoint: ptrace (process injection detection) ─────────────────────────

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns   = bpf_ktime_get_ns();
    e->pid     = pid;
    e->ppid    = _get_ppid();
    e->uid     = bpf_get_current_uid_gid() >> 32;
    e->gid     = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type = SC_PTRACE;
    e->flags   = (__u8)(ctx->args[0] & 0xFF); // PTRACE_* request type
    e->net_port = 0;
    e->net_ip4  = ((__u32)ctx->args[1]); // tracee PID

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_snprintf(e->resource, sizeof(e->resource),
                       "ptrace_target_pid=%u", e->net_ip4);

    _update_entropy_map(pid, SC_PTRACE);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── LSM Hook: lsm/bprm_check_security ────────────────────────────────────────
// Fires after the kernel resolves the binary path (post-symlink, post-dentry).
// Eliminates the TOCTOU race present in sys_enter_execve tracepoints, where
// the filename pointer can be swapped between the syscall entry and the open.

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;

    int action = _check_enforce(pid);
    if (action == ENF_SIGKILL)  bpf_send_signal(9);
    else if (action == ENF_SIGSTOP) bpf_send_signal(19);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns    = bpf_ktime_get_ns();
    e->pid      = pid;
    e->ppid     = _get_ppid();
    e->uid      = bpf_get_current_uid_gid() >> 32;
    e->gid      = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type  = SC_EXEC;
    e->flags    = 0x02;   // 0x02 = LSM-sourced (vs 0x00 for tracepoint)
    e->net_port = 0;
    e->net_ip4  = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    // bprm->filename is the kernel-resolved path — immune to TOCTOU
    bpf_core_read_str(e->resource, sizeof(e->resource), bprm->filename);

    _update_entropy_map(pid, SC_EXEC);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── LSM Hook: lsm/file_open ───────────────────────────────────────────────────
// Fires after dentry resolution; captures the kernel-canonical path via
// bpf_d_path(), which follows mount points and bind mounts correctly.

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;

    __u32 fflags  = BPF_CORE_READ(file, f_flags);
    __u8  sc_type = (fflags & O_WRONLY) ? SC_FILE_W : SC_FILE_R;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns    = bpf_ktime_get_ns();
    e->pid      = pid;
    e->ppid     = _get_ppid();
    e->uid      = bpf_get_current_uid_gid() >> 32;
    e->gid      = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type  = sc_type;
    e->flags    = 0x02;
    e->net_port = 0;
    e->net_ip4  = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    // bpf_d_path resolves symlinks and bind-mounts — no TOCTOU
    bpf_d_path(&file->f_path, e->resource, sizeof(e->resource));

    _update_entropy_map(pid, sc_type);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── LSM Hook: lsm/socket_connect ─────────────────────────────────────────────
// Fires at socket_connect LSM check — after the kernel validates the socket
// and resolves the destination, before the actual TCP SYN is sent.

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (address->sa_family != AF_INET) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;

    struct sockaddr_in *sin = (struct sockaddr_in *)address;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __u32 ip   = BPF_CORE_READ(sin, sin_addr.s_addr);
    __u16 port = bpf_ntohs(BPF_CORE_READ(sin, sin_port));

    e->ts_ns    = bpf_ktime_get_ns();
    e->pid      = pid;
    e->ppid     = _get_ppid();
    e->uid      = bpf_get_current_uid_gid() >> 32;
    e->gid      = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type  = SC_NET_CON;
    e->flags    = 0x02;
    e->net_port = port;
    e->net_ip4  = ip;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_snprintf(e->resource, sizeof(e->resource),
                       "%u.%u.%u.%u:%u",
                       (ip >>  0) & 0xFF, (ip >>  8) & 0xFF,
                       (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, port);

    _update_entropy_map(pid, SC_NET_CON);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── Tracepoint: sys_enter_prctl (comm masquerading detection) ─────────────────
// Fires on every prctl() syscall. We only care about PR_SET_NAME (option=15),
// which changes the thread's visible name (comm field) — used by malware to
// masquerade as a trusted process (MITRE T1036.004).
//
// ARM64 registers: x0=option, x1=name_ptr (new comm)
// The event carries:
//   resource      = new name (the fake identity being assumed)
//   original_comm = old name (the identity being abandoned)
// The lineage_map prctl_rename_count is incremented atomically.

SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl(struct trace_event_raw_sys_enter *ctx) {
    int option = (int)ctx->args[0];
    if (option != PR_SET_NAME)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns   = bpf_ktime_get_ns();
    e->pid     = pid;
    e->ppid    = _get_ppid();
    e->uid     = bpf_get_current_uid_gid() >> 32;
    e->gid     = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->sc_type = SC_PRCTL;
    e->flags   = PR_SET_NAME;   // indicate which prctl option
    e->net_port = 0;
    e->net_ip4  = 0;

    // ARM64: x0=option, x1=new_name_ptr
    e->arm64_regs[0] = ctx->args[0];  // PR_SET_NAME
    e->arm64_regs[1] = ctx->args[1];  // new name ptr
    e->arm64_regs[2] = 0;

    // original_comm = current comm (before rename)
    bpf_get_current_comm(e->original_comm, sizeof(e->original_comm));
    // comm field = current comm (we fill it the same way for consistency)
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    // resource = new name being set (the masquerade identity)
    bpf_probe_read_user_str(e->resource, sizeof(e->resource),
                            (const void *)ctx->args[1]);

    // Update lineage: mark this PID as having renamed itself
    struct lineage_t *lin = bpf_map_lookup_elem(&lineage_map, &pid);
    if (lin) {
        lin->prctl_rename_count++;
        lin->last_prctl_ns = e->ts_ns;
        // Update current_comm to the new name
        bpf_probe_read_user_str(lin->current_comm, sizeof(lin->current_comm),
                                (const void *)ctx->args[1]);
    } else {
        // First time we see this PID — create lineage entry with rename count=1
        struct lineage_t init = {};
        init.ppid            = e->ppid;
        init.prctl_rename_count = 1;
        init.first_seen_ns   = e->ts_ns;
        init.last_prctl_ns   = e->ts_ns;
        bpf_get_current_comm(init.original_comm, sizeof(init.original_comm));
        bpf_probe_read_user_str(init.current_comm, sizeof(init.current_comm),
                                (const void *)ctx->args[1]);
        bpf_map_update_elem(&lineage_map, &pid, &init, BPF_ANY);
    }

    _update_entropy_map(pid, SC_PRCTL);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

//── XDP Quarantine Hook ───────────────────────────────────────────────────────
// Drops all ingress/egress frames for quarantined network namespaces.
// Attached to the host-facing NIC in XDP native mode for < 1μs drop latency.

SEC("xdp")
int xdp_quarantine(struct xdp_md *ctx) {
    __u64 netns_cookie = bpf_get_netns_cookie(ctx);
    __u8 *hit = bpf_map_lookup_elem(&xdp_quarantine_map, &netns_cookie);
    if (hit && *hit == 1)
        return XDP_DROP;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
