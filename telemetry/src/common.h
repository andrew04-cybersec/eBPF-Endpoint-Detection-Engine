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

/*file_open caps; unmeasured first values */
#define FILE_PEEK 128		/*bytes of the path the kernel filter looks at*/
#define FILE_PATH_CAP 256	/*bytes of path kept in the record (includes NUL)*/
#define HOME_USER_SCAN 32	/*how far into /home/ the filter looks for /.ssh/*/

/*names kept apart from AF_INET so loader can include the socket headers*/
#define EVT_AF_INET 2
#define EVT_AF_INET6 10

/*indexes of the openat counters*/
enum {
	STAT_OPENAT_SEEN,
	STAT_OPENAT_BLANK,
	STAT_FILE_EMITTED,
	STAT_COUNT,
};

enum priv_syscall {
	PRIV_SETUID = 1,
	PRIV_SETREUID = 2,
	PRIV_SETRESUID = 3,
	PRIV_SETGID = 4,
	PRIV_SETRESGID = 5,
};

enum rec_type {
	REC_EXEC_ATTEMPT = 1,
	REC_EXEC_SUCCESS = 2,
	REC_EXIT = 3,
	REC_FILE_OPEN = 4,
	REC_NET_CONNECT = 5,
	REC_PRIV_CHANGE = 6,
};

/*bits in rec_hdr.flags*/
#define FLAG_FILENAME_TRUNC (1u << 0)
#define FLAG_ARGV_TRUNC (1u << 1)
#define FLAG_READ_FAILED (1u << 2)
#define FLAG_HAS_RET (1u << 3)

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

struct rec_file_open {
	struct rec_hdr h;
	__s32 open_flags;
	__s32 ret;		/*valid only with FLAG_HAS_RET*/
	char path[FILE_PATH_CAP];
};

struct rec_net_connect {
	struct rec_hdr h;
	__u16 family;
	__u16 port;		/*host order*/
	__u32 pad;
	__u8 addr[16];		/*network order which is first 4 bytes for IPv4*/
};

struct rec_priv_change {
	struct rec_hdr h;
	__u32 syscall;
	__u32 nids;
	__u32 ids[3];
	__u32 pad;
};

#endif
