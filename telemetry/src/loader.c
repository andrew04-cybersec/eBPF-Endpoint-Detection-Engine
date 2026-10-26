// Loader: attaches the exec/exit program and prints one JSON object per line.
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "exec_exit.skel.h"

#define SCHEMA_VERSION 1

/*worst case is that every byte escaped as six characters plus any punctuation*/
#define LINE_CAP 32768

#define POLL_MS 200

struct jbuf {
	char data[LINE_CAP];
	size_t len;
	bool lossy;
	bool overflow;
};

static struct jbuf line;
static volatile sig_atomic_t stop;
static bool verbose;

static void jput(struct jbuf *b, const char *s, size_t n)
{
	if (b->len + n >= sizeof(b->data)) {
		b->overflow = true;
		return;
	}
	memcpy(b->data + b->len, s, n);
	b->len += n;
}

static void jprintf(struct jbuf *b, const char *fmt, ...)
{
	size_t room = sizeof(b->data) - b->len;
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(b->data + b->len, room, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= room) {
		b->overflow = true;
		return;
	}
	b->len += n;
}

/*length of the valid UTF-8 sequence at s (or 0 if first byte starts none)*/
static size_t utf8_len(const unsigned char *s, size_t n)
{
	unsigned char c = s[0], lo = 0x80, hi = 0xBF;
	size_t need, i;

	if (c >= 0xC2 && c <= 0xDF) {
		need = 1;
	} else if (c >= 0xE0 && c <= 0xEF) {
		need = 2;
		if (c == 0xE0)
			lo = 0xA0;
		if (c == 0xED)
			hi = 0x9F;
	} else if (c >= 0xF0 && c <= 0xF4) {
		need = 3;
		if (c == 0xF0)
			lo = 0x90;
		if (c == 0xF4)
			hi = 0x8F;
	} else {
		return 0;
	}
	if (n < need + 1 || s[1] < lo || s[1] > hi)
		return 0;
	for (i = 2; i <= need; i++)
		if ((s[i] & 0xC0) != 0x80)
			return 0;
	return need + 1;
}

/*write a JSON string; invalid UTF-8 bytes become U+FFFD and set b->lossy*/
static void jstr(struct jbuf *b, const char *str, size_t cap)
{
	const unsigned char *s = (const unsigned char *)str;
	size_t n = strnlen(str, cap), i = 0, l;

	jput(b, "\"", 1);
	while (i < n) {
		unsigned char c = s[i];

		if (c >= 0x80) {
			l = utf8_len(s + i, n - i);
			if (l) {
				jput(b, (const char *)s + i, l);
				i += l;
			} else {
				jput(b, "\xEF\xBF\xBD", 3);
				b->lossy = true;
				i++;
			}
			continue;
		}
		switch (c) {
		case '"':
			jput(b, "\\\"", 2);
			break;
		case '\\':
			jput(b, "\\\\", 2);
			break;
		case '\n':
			jput(b, "\\n", 2);
			break;
		case '\r':
			jput(b, "\\r", 2);
			break;
		case '\t':
			jput(b, "\\t", 2);
			break;
		default:
			if (c < 0x20 || c == 0x7f)
				jprintf(b, "\\u%04x", c);
			else
				jput(b, (const char *)&c, 1);
		}
		i++;
	}
	jput(b, "\"", 1);
}

static const char *tf(bool v)
{
	return v ? "true" : "false";
}

static void put_envelope(struct jbuf *b, const char *type, const struct rec_hdr *h)
{
	jprintf(b, "{\"schema_version\":%d,\"type\":\"%s\",\"ts_ns\":%llu,\"pid\":%u,\"tid\":%u,\"comm\":",
		SCHEMA_VERSION, type, (unsigned long long)h->ts_ns, h->pid, h->tid);
	jstr(b, h->comm, COMM_LEN);
}

static void put_identity(struct jbuf *b, const struct rec_hdr *h)
{
	jprintf(b, ",\"ppid\":%u,\"uid\":%u,\"gid\":%u,\"start_time_ns\":%llu",
		h->ppid, h->uid, h->gid, (unsigned long long)h->start_time_ns);
}

static void emit(struct jbuf *b)
{
	if (b->overflow) {
		fprintf(stderr, "loader: line too long, event dropped\n");
		return;
	}
	jput(b, "\n", 1);
	fwrite(b->data, 1, b->len, stdout);
	fflush(stdout);
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct rec_hdr *h = data;
	struct jbuf *b = &line;

	b->len = 0;
	b->lossy = false;
	b->overflow = false;

	if (size < sizeof(*h)) {
		fprintf(stderr, "loader: short record (%zu bytes)\n", size);
		return 0;
	}

	switch (h->type) {
	case REC_EXEC_ATTEMPT: {
		const struct rec_exec_attempt *e = data;
		unsigned int i, argc = e->argc;

		if (size < sizeof(*e))
			goto bad;
		if (argc > ARGV_MAX_ARGS)
			argc = ARGV_MAX_ARGS;
		put_envelope(b, "exec_attempt", h);
		jput(b, ",\"filename\":", 12);
		jstr(b, e->filename, FILENAME_CAP);
		jprintf(b, ",\"filename_truncated\":%s,\"argv\":[", tf(h->flags & FLAG_FILENAME_TRUNC));
		for (i = 0; i < argc; i++) {
			if (i)
				jput(b, ",", 1);
			jstr(b, e->argv[i], ARGV_ARG_CAP);
		}
		jprintf(b, "],\"argv_truncated\":%s", tf(h->flags & FLAG_ARGV_TRUNC));
		put_identity(b, h);
		break;
	}
	case REC_EXEC_SUCCESS: {
		const struct rec_exec_success *e = data;

		if (size < sizeof(*e))
			goto bad;
		put_envelope(b, "exec_success", h);
		jput(b, ",\"filename\":", 12);
		jstr(b, e->filename, FILENAME_CAP);
		jprintf(b, ",\"filename_truncated\":%s,\"old_pid\":%u",
			tf(h->flags & FLAG_FILENAME_TRUNC), e->old_pid);
		put_identity(b, h);
		break;
	}
	case REC_EXIT: {
		const struct rec_exit *e = data;
		int raw;

		if (size < sizeof(*e))
			goto bad;
		raw = e->exit_code;
		put_envelope(b, "exit", h);
		/* exit_code is the raw kernel value; status and signal are decoded from it. */
		jprintf(b, ",\"exit_code\":%d,\"exit_status\":%d,\"exit_signal\":%d",
			raw, (raw >> 8) & 0xff, raw & 0x7f);
		put_identity(b, h);
		break;
	}
	default:
		goto bad;
	}

	if (h->type != REC_EXIT)
		jprintf(b, ",\"user_read_failed\":%s", tf(h->flags & FLAG_READ_FAILED));
	jprintf(b, ",\"lossy_encoding\":%s}", tf(b->lossy));
	emit(b);
	return 0;

bad:
	fprintf(stderr, "loader: unknown or short record (type %u, %zu bytes)\n", h->type, size);
	return 0;
}

/*report records the kernel side since it was dropped since the last report*/
static void report_lost(int map_fd, int ncpu, __u64 *vals, __u64 *last)
{
	struct rec_hdr h = {};
	__u32 key = 0;
	__u64 total = 0;
	struct timespec ts;
	struct jbuf *b = &line;
	int i;

	if (bpf_map_lookup_elem(map_fd, &key, vals))
		return;
	for (i = 0; i < ncpu; i++)
		total += vals[i];
	if (total == *last)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	h.ts_ns = (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
	h.pid = getpid();
	h.tid = syscall(SYS_gettid);
	prctl(PR_GET_NAME, h.comm);

	b->len = 0;
	b->lossy = false;
	b->overflow = false;
	put_envelope(b, "lost", &h);
	jprintf(b, ",\"dropped\":%llu}", (unsigned long long)(total - *last));
	emit(b);
	*last = total;
}

static int print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static void on_signal(int sig)
{
	stop = 1;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"  -t, --all-thread-exits   report every thread exit, not one per process\n"
		"  -r, --ringbuf-bytes N    override the ring buffer size (power of two)\n"
		"  -v, --verbose            libbpf debug output on stderr\n"
		"  -h, --help               this text\n", prog);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "all-thread-exits", no_argument, NULL, 't' },
		{ "ringbuf-bytes", required_argument, NULL, 'r' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ 0 }
	};
	bool all_threads = false;
	unsigned long rb_bytes = 0;
	struct exec_exit_bpf *skel;
	struct ring_buffer *rb = NULL;
	struct sigaction sa = { .sa_handler = on_signal };
	__u64 *vals = NULL, last_drops = 0;
	int c, err, ncpu;

	while ((c = getopt_long(argc, argv, "tr:vh", opts, NULL)) != -1) {
		switch (c) {
		case 't':
			all_threads = true;
			break;
		case 'r':
			rb_bytes = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			verbose = true;
			break;
		default:
			usage(argv[0]);
			return c == 'h' ? 0 : 2;
		}
	}

	libbpf_set_print(print_fn);

	skel = exec_exit_bpf__open();
	if (!skel) {
		fprintf(stderr, "loader: failed to open the BPF skeleton\n");
		return 1;
	}
	skel->rodata->all_thread_exits = all_threads;
	if (rb_bytes)
		bpf_map__set_max_entries(skel->maps.rb, rb_bytes);

	err = exec_exit_bpf__load(skel);
	if (err) {
		fprintf(stderr, "loader: failed to load the BPF program (%d). Root is required.\n", err);
		goto out;
	}
	err = exec_exit_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "loader: failed to attach (%d)\n", err);
		goto out;
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "loader: failed to create the ring buffer reader\n");
		goto out;
	}
	ncpu = libbpf_num_possible_cpus();
	vals = calloc(ncpu > 0 ? ncpu : 1, sizeof(*vals));
	if (!vals) {
		err = -ENOMEM;
		goto out;
	}

	/*no SA_RESTART so a signal interrupts the poll*/
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	fprintf(stderr, "loader: attached\n");

	while (!stop) {
		err = ring_buffer__poll(rb, POLL_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "loader: poll failed (%d)\n", err);
			break;
		}
		report_lost(bpf_map__fd(skel->maps.drops), ncpu, vals, &last_drops);
	}
	err = 0;

	/*drain what is left before exiting*/
	ring_buffer__consume(rb);
	report_lost(bpf_map__fd(skel->maps.drops), ncpu, vals, &last_drops);

out:
	free(vals);
	ring_buffer__free(rb);
	exec_exit_bpf__destroy(skel);
	return err < 0 ? 1 : err;
}
