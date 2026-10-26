//eBPF program: exec attempt, exec success and process exit records
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "sensitive_paths.h"

char LICENSE[] SEC("license") = "GPL";

/*set by the loader and when it is true than every thread exit is reported instead of just the last exit being reported*/
const volatile bool all_thread_exits = false;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} rb SEC(".maps");

/*count of records dropped because ring buffer full*/
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

/*processes of which the exit was already reported and guards against two threads in which both see the group as finished.*/
struct exit_key {
	__u32 tgid;
	__u32 pad;
	__u64 start;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct exit_key);
	__type(value, __u8);
} exited SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *v = bpf_map_lookup_elem(&drops, &key);

	if (v)
		(*v)++;
}

static __always_inline void fill_hdr(struct rec_hdr *h, __u32 type)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	__u64 id = bpf_get_current_pid_tgid();

	h->type = type;
	h->flags = 0;
	h->ts_ns = bpf_ktime_get_ns();
	h->pid = id >> 32;
	h->tid = (__u32)id;
	h->ppid = BPF_CORE_READ(t, real_parent, tgid);
	h->uid = BPF_CORE_READ(t, real_cred, uid.val);
	h->gid = BPF_CORE_READ(t, real_cred, gid.val);
	h->start_time_ns = BPF_CORE_READ(t, group_leader, start_time);
	bpf_get_current_comm(h->comm, sizeof(h->comm));
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec_attempt(struct trace_event_raw_sys_enter *ctx)
{
	const char *fname = (const char *)ctx->args[0];
	const char *const *argv = (const char *const *)ctx->args[1];
	struct rec_exec_attempt *e;
	__u32 argc = 0;
	long n;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill_hdr(&e->h, REC_EXEC_ATTEMPT);

	n = bpf_probe_read_user_str(e->filename, sizeof(e->filename), fname);
	if (n < 0) {
		e->filename[0] = 0;
		e->h.flags |= FLAG_READ_FAILED;
	} else if (n >= (long)sizeof(e->filename)) {
		e->h.flags |= FLAG_FILENAME_TRUNC;
	}

#pragma unroll
	for (__u32 i = 0; i < ARGV_MAX_ARGS; i++) {
		const char *argp = NULL;
		long len;

		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0) {
			e->h.flags |= FLAG_READ_FAILED;
			break;
		}
		if (!argp)
			break;
		len = bpf_probe_read_user_str(e->argv[i], ARGV_ARG_CAP, argp);
		if (len < 0) {
			e->argv[i][0] = 0;
			e->h.flags |= FLAG_READ_FAILED;
		} else if (len >= ARGV_ARG_CAP) {
			e->h.flags |= FLAG_ARGV_TRUNC;
		}
		argc = i + 1;
	}

	/*all slots used and any further argument means the list was cut*/
	if (argc == ARGV_MAX_ARGS) {
		const char *more = NULL;

		if (bpf_probe_read_user(&more, sizeof(more), &argv[ARGV_MAX_ARGS]) == 0 && more)
			e->h.flags |= FLAG_ARGV_TRUNC;
	}
	e->argc = argc;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec_success(struct trace_event_raw_sched_process_exec *ctx)
{
	struct rec_exec_success *e;
	unsigned short off;
	long n;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill_hdr(&e->h, REC_EXEC_SUCCESS);
	e->old_pid = ctx->old_pid;

	/*filename is a __data_loc string... offset in the low 16 bits*/
	off = ctx->__data_loc_filename & 0xFFFF;
	n = bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (void *)ctx + off);
	if (n < 0) {
		e->filename[0] = 0;
		e->h.flags |= FLAG_READ_FAILED;
	} else if (n >= (long)sizeof(e->filename)) {
		e->h.flags |= FLAG_FILENAME_TRUNC;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct rec_exit *e;

	/*this fires once per thread and then the live count is already decremented here so the last thread of a process sees zero*/
	if (!all_thread_exits) {
		struct exit_key k = {};
		__u8 one = 1;

		if (BPF_CORE_READ(t, signal, live.counter) != 0)
			return 0;
		k.tgid = BPF_CORE_READ(t, tgid);
		k.start = BPF_CORE_READ(t, group_leader, start_time);
		if (bpf_map_update_elem(&exited, &k, &one, BPF_NOEXIST) != 0)
			return 0;
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill_hdr(&e->h, REC_EXIT);
	e->exit_code = BPF_CORE_READ(t, exit_code);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*openat counters... summed by the loader */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} file_stats SEC(".maps");

/*open arguments saved at entry and used when the path is read at exit*/
struct openat_args {
	const char *path;
	int flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct openat_args);
} openat_saved SEC(".maps");

static __always_inline void stat_inc(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&file_stats, &key);

	if (v)
		(*v)++;
}

/*true if p[off..] starts with the first len bytes of lit*/
static __always_inline bool at_prefix(const char *p, int off, const char *lit, int len)
{
#pragma unroll
	for (int i = 0; i < len; i++)
		if (p[off + i] != lit[i])
			return false;
	return true;
}

static __always_inline bool is_sensitive(const char *p)
{
#define X(lit) if (at_prefix(p, 0, lit, sizeof(lit) - 1) && p[sizeof(lit) - 1] == 0) return true;
	SENSITIVE_EXACT(X)
#undef X
#define X(lit) if (at_prefix(p, 0, lit, sizeof(lit) - 1)) return true;
	SENSITIVE_PREFIX(X)
#undef X
	if (at_prefix(p, 0, "/home/", 6)) {
#pragma unroll
		for (int k = 6; k < 6 + HOME_USER_SCAN; k++)
			if (at_prefix(p, k, "/.ssh/", 6))
				return true;
	}
	return false;
}

/*filter the path and emit a file_open record if it is on the list*/
static __always_inline int file_check_and_emit(const char *path, int oflags, bool has_ret, long ret)
{
	char peek[FILE_PEEK] = {};
	struct rec_file_open *e;
	long n;

	stat_inc(STAT_OPENAT_SEEN);
	n = bpf_probe_read_user_str(peek, sizeof(peek), path);
	if (n <= 1) {
		stat_inc(STAT_OPENAT_BLANK);
		return 0;
	}
	if (!is_sensitive(peek))
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill_hdr(&e->h, REC_FILE_OPEN);
	e->open_flags = oflags;
	e->ret = ret;
	if (has_ret)
		e->h.flags |= FLAG_HAS_RET;

	n = bpf_probe_read_user_str(e->path, sizeof(e->path), path);
	if (n < 0) {
		e->path[0] = 0;
		e->h.flags |= FLAG_READ_FAILED;
	} else if (n >= (long)sizeof(e->path)) {
		e->h.flags |= FLAG_FILENAME_TRUNC;
	}

	stat_inc(STAT_FILE_EMITTED);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*default which is... read the path at entry*/
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_entry(struct trace_event_raw_sys_enter *ctx)
{
	return file_check_and_emit((const char *)ctx->args[1], (int)ctx->args[2], false, 0);
}

/*exit mode which is... save the arguments at entry and read the path at exit*/
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_save(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct openat_args a = {
		.path = (const char *)ctx->args[1],
		.flags = (int)ctx->args[2],
	};

	bpf_map_update_elem(&openat_saved, &id, &a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct openat_args *a = bpf_map_lookup_elem(&openat_saved, &id);
	struct openat_args saved;

	if (!a)
		return 0;
	saved = *a;
	bpf_map_delete_elem(&openat_saved, &id);
	return file_check_and_emit(saved.path, saved.flags, true, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	const void *uaddr = (const void *)ctx->args[1];
	int alen = (int)ctx->args[2];
	struct rec_net_connect *e;
	__u16 family = 0;

	if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
		return 0;

	if (family == EVT_AF_INET) {
		struct sockaddr_in sa = {};

		if (alen < (int)sizeof(sa) ||
		    bpf_probe_read_user(&sa, sizeof(sa), uaddr) < 0)
			return 0;
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (!e) {
			count_drop();
			return 0;
		}
		fill_hdr(&e->h, REC_NET_CONNECT);
		e->family = family;
		e->port = bpf_ntohs(sa.sin_port);
		e->pad = 0;
		__builtin_memset(e->addr, 0, sizeof(e->addr));
		__builtin_memcpy(e->addr, &sa.sin_addr, 4);
	} else if (family == EVT_AF_INET6) {
		struct sockaddr_in6 sa = {};

		if (alen < (int)sizeof(sa) ||
		    bpf_probe_read_user(&sa, sizeof(sa), uaddr) < 0)
			return 0;
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (!e) {
			count_drop();
			return 0;
		}
		fill_hdr(&e->h, REC_NET_CONNECT);
		e->family = family;
		e->port = bpf_ntohs(sa.sin6_port);
		e->pad = 0;
		__builtin_memcpy(e->addr, &sa.sin6_addr, 16);
	} else {
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*ids are passed by value so every ctx->args read stays at a constant offset from ctx*/
static __always_inline int priv_emit(__u32 sc, __u32 nids, __u32 a0, __u32 a1, __u32 a2)
{
	struct rec_priv_change *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill_hdr(&e->h, REC_PRIV_CHANGE);
	e->syscall = sc;
	e->nids = nids;
	e->pad = 0;
	e->ids[0] = a0;
	e->ids[1] = a1;
	e->ids[2] = a2;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
	return priv_emit(PRIV_SETUID, 1, (__u32)ctx->args[0], 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int handle_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	return priv_emit(PRIV_SETREUID, 2, (__u32)ctx->args[0], (__u32)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	return priv_emit(PRIV_SETRESUID, 3, (__u32)ctx->args[0], (__u32)ctx->args[1], (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx)
{
	return priv_emit(PRIV_SETGID, 1, (__u32)ctx->args[0], 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int handle_setresgid(struct trace_event_raw_sys_enter *ctx)
{
	return priv_emit(PRIV_SETRESGID, 3, (__u32)ctx->args[0], (__u32)ctx->args[1], (__u32)ctx->args[2]);
}
