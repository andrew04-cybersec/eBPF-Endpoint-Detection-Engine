#!/bin/bash
#run the loader, execute a fixed workload, stop the loader, validate the output.
#WSL usage:  sudo bash tests/run_test.sh        (set NO_BCC=1 to skip the BCC comparison)
#output is saved under tests/out/<timestamp>/ and is kept as evidence.
set -u
cd "$(dirname "$0")/.." || exit 2

if [ "$(id -u)" -ne 0 ]; then
	echo "run this with sudo" >&2
	exit 2
fi
LOADER=build/exec_exit_loader
if [ ! -x "$LOADER" ]; then
	echo "build first: make" >&2
	exit 2
fi

MAX_ARGS=$(awk '/#define ARGV_MAX_ARGS/ {print $3}' src/common.h)
ARG_CAP=$(awk '/#define ARGV_ARG_CAP/ {print $3}' src/common.h)
BURST=50

OUT=tests/out/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "ARGV_MAX_ARGS: $MAX_ARGS"
	echo "ARGV_ARG_CAP: $ARG_CAP"
	echo "burst: $BURST"
	echo "sudo_uid: ${SUDO_UID:-none}"
} > "$OUT/env.txt"

PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null; done
}
trap cleanup EXIT

#start_loader <events file> <stderr file> [loader args]
start_loader() {
	local ev=$1 err=$2
	shift 2
	"$LOADER" "$@" > "$ev" 2> "$err" &
	LOADER_PID=$!
	PIDS+=("$LOADER_PID")
	for _ in $(seq 1 100); do
		grep -q "attached" "$err" 2>/dev/null && return 0
		kill -0 "$LOADER_PID" 2>/dev/null || break
		sleep 0.1
	done
	echo "loader did not attach:" >&2
	cat "$err" >&2
	return 1
}

stop_loader() {
	sleep 1
	kill -INT "$LOADER_PID" 2>/dev/null
	wait "$LOADER_PID"
	echo "loader exit status: $?" >> "$OUT/env.txt"
}

threads_cmd() {
	#the marker is separate argument, the long -c string is cut at the argument cap
	python3 -c "import threading,time
ts=[threading.Thread(target=time.sleep,args=(0.1,)) for _ in range(3)]
[t.start() for t in ts]
[t.join() for t in ts]" EVT_THREADS
}

#opens of listed paths, a normal file, and listed paths that do not exist
file_cmds() {
	/bin/cat /etc/shadow > /dev/null
	/bin/cat /etc/passwd > /dev/null
	/bin/cat /etc/os-release > /dev/null
	/bin/cat /root/.ssh/evt_missing_key 2> /dev/null || true
	/bin/cat /home/evt_nouser/.ssh/id_rsa 2> /dev/null || true
}

#plain opens so the entry and exit modes see the same load
load_cmds() {
	for _ in $(seq 1 20); do /bin/ls /usr/lib > /dev/null; done
}

#listener and client in one process... prints the port (or 0 if the address is unavailable)
NET_PY='import socket,sys
host = sys.argv[2]
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
try:
    s = socket.socket(fam)
    s.bind((host, 0))
    s.listen(1)
except OSError:
    print(0)
    sys.exit(0)
port = s.getsockname()[1]
c = socket.socket(fam)
c.connect((host, port))
a, _ = s.accept()
a.close()
c.close()
s.close()
print(port)'

#main run which for this is that BCC tools run alongside for comparison
start_loader "$OUT/events.jsonl" "$OUT/loader.stderr" || exit 1

BCC_PIDS=()
if [ "${NO_BCC:-0}" != 1 ] && command -v execsnoop-bpfcc >/dev/null && command -v exitsnoop-bpfcc >/dev/null; then
	PYTHONUNBUFFERED=1 execsnoop-bpfcc -x > "$OUT/execsnoop.txt" 2> "$OUT/execsnoop.err" &
	BCC_PIDS+=($!)
	PYTHONUNBUFFERED=1 exitsnoop-bpfcc > "$OUT/exitsnoop.txt" 2> "$OUT/exitsnoop.err" &
	BCC_PIDS+=($!)
	PIDS+=("${BCC_PIDS[@]}")
	for f in execsnoop exitsnoop; do
		for _ in $(seq 1 90); do
			[ -s "$OUT/$f.txt" ] && break
			sleep 1
		done
	done
	echo "bcc tools: ready" >> "$OUT/env.txt"
else
	echo "bcc tools: skipped" >> "$OUT/env.txt"
fi

#workload
/bin/echo EVT_OK > /dev/null
/nonexistent/evt_program EVT_FAIL 2> /dev/null || true
sh -c 'ls / > /dev/null; cat /etc/hostname > /dev/null # EVT_CHAIN'
for _ in $(seq 1 "$BURST"); do /bin/true EVT_BURST; done
if [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" != 0 ]; then
	setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --clear-groups /bin/echo EVT_UID > /dev/null
fi
{ sh -c 'exit 7 # EVT_EXIT7'; } 2> /dev/null
{ sh -c 'kill -9 $$ # EVT_KILL9'; } 2> /dev/null
threads_cmd
/bin/echo EVT_MANYARGS $(seq 1 $((MAX_ARGS + 5))) > /dev/null
LONG=$(head -c $((ARG_CAP + 50)) /dev/zero | tr '\0' 'A')
/bin/echo EVT_LONGARG "$LONG" > /dev/null
/bin/echo EVT_BADUTF8 $'\xff\xfe' > /dev/null
file_cmds
load_cmds
NET4_PORT=$(python3 -c "$NET_PY" EVT_NET4 127.0.0.1)
NET6_PORT=$(python3 -c "$NET_PY" EVT_NET6 ::1)
echo "net4_port: $NET4_PORT" >> "$OUT/env.txt"
echo "net6_port: $NET6_PORT" >> "$OUT/env.txt"
if [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" != 0 ]; then
	python3 -c "import os,sys
u = int(sys.argv[2])
g = int(sys.argv[3])
os.setgid(g)
os.setresgid(g, g, g)
os.setreuid(u, u)
os.setresuid(u, u, u)
os.setuid(u)" EVT_PRIV "$SUDO_UID" "$SUDO_GID"
fi

sleep 1
if [ "${#BCC_PIDS[@]}" -gt 0 ]; then
	kill -INT "${BCC_PIDS[@]}" 2>/dev/null
	wait "${BCC_PIDS[@]}" 2>/dev/null
fi
stop_loader

#second run reports every thread exit to show the raw per-thread behavior.
start_loader "$OUT/events_threads.jsonl" "$OUT/loader_threads.stderr" --all-thread-exits || exit 1
threads_cmd
stop_loader

#file_open with the path read at exit and then at entry on the same commands
start_loader "$OUT/events_fileexit.jsonl" "$OUT/loader_fileexit.stderr" || exit 1
file_cmds
load_cmds
stop_loader
start_loader "$OUT/events_fileentry.jsonl" "$OUT/loader_fileentry.stderr" --file-at-entry || exit 1
file_cmds
load_cmds
stop_loader

#validate
BCC_ARGS=()
[ -s "$OUT/execsnoop.txt" ] && BCC_ARGS+=(--execsnoop "$OUT/execsnoop.txt")
[ -s "$OUT/exitsnoop.txt" ] && BCC_ARGS+=(--exitsnoop "$OUT/exitsnoop.txt")
python3 tests/validate.py "$OUT/events.jsonl" --threads-all "$OUT/events_threads.jsonl" \
	"${BCC_ARGS[@]}" --max-args "$MAX_ARGS" --arg-cap "$ARG_CAP" --burst "$BURST" \
	--sudo-uid "${SUDO_UID:-0}" --sudo-gid "${SUDO_GID:-0}" \
	--net4-port "${NET4_PORT:-0}" --net6-port "${NET6_PORT:-0}" \
	--file-exit "$OUT/events_fileexit.jsonl" --file-entry "$OUT/events_fileentry.jsonl" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}
grep -H file_stats "$OUT"/loader*.stderr | tee -a "$OUT/report.txt"

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in telemetry/$OUT"
exit "$STATUS"
