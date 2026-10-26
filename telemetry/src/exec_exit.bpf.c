//eBPF program: exec attempt, exec success and process exit records
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

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
