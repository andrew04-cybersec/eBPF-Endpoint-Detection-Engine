/*record layouts shared by the eBPF program and the loader*/
#ifndef TELEMETRY_COMMON_H
#define TELEMETRY_COMMON_H

/*the includer must provide __u8/__u16/__u32/__u64 first before anything else*/

#define COMM_LEN 16

/*capture caps; conservative first values are going to be revisited after measurement*/
#define FILENAME_CAP 256	/*bytes; including the terminating NUL*/
#define ARGV_MAX_ARGS 16	/*arguments captured per exec attempt*/
#define ARGV_ARG_CAP 128	/*bytes per argument... including the NUL*/

/*ring buffer size in bytes, must be a power of two and a multiple of the page size*/
#define RINGBUF_BYTES (1u << 22)

enum rec_type {
	REC_EXEC_ATTEMPT = 1,
	REC_EXEC_SUCCESS = 2,
	REC_EXIT = 3,
};

/*bits in rec_hdr.flags*/
#define FLAG_FILENAME_TRUNC (1u << 0)
#define FLAG_ARGV_TRUNC (1u << 1)
#define FLAG_READ_FAILED (1u << 2)

struct rec_hdr {
	__u32 type;
	__u32 flags;
	__u64 ts_ns;		/*kernel monotonic clock*/
	__u64 start_time_ns;	/*thread group leader start, same clock*/
	__u32 pid;		/*tgid*/
	__u32 tid;
	__u32 ppid;
	__u32 uid;		/*real uid*/
	__u32 gid;		/*real gid*/
	char comm[COMM_LEN];
};

struct rec_exec_attempt {
	struct rec_hdr h;
	__u32 argc;		/*argv slots filled*/
	__u32 pad;
	char filename[FILENAME_CAP];
	char argv[ARGV_MAX_ARGS][ARGV_ARG_CAP];
};

struct rec_exec_success {
	struct rec_hdr h;
	__u32 old_pid;
	__u32 pad;
	char filename[FILENAME_CAP];
};

struct rec_exit {
	struct rec_hdr h;
	__s32 exit_code;	/*task exit_code as the kernel stores it*/
	__u32 pad;
};

#endif
