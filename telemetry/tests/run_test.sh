#!/bin/bash
#run the loader and execute a fixed workload, then stop the loader and validate the output
#WSL usage: sudo bash tests/run_test.sh (set NO_BCC=1 to skip the BCC comparison)
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

#write-intent cases use these names and the script refuses to run if any of them exist and then finally will remove what it made on every exit path
D8_HOME=/home/evt_d8user
D8_CRON=/etc/cron.d/evt_d8_cron
D8_UNIT=/etc/systemd/system/evt_d8_unit.service
D8_HOME_MADE=0
for p in "$D8_HOME" "$D8_CRON" "$D8_UNIT"; do
	if [ -e "$p" ]; then
		echo "$p already exists, so it is not touched; remove it by hand and run again" >&2
		exit 2
	fi
done
PRELOAD_EXISTED=0
RCLOCAL_EXISTED=0
[ -e /etc/ld.so.preload ] && PRELOAD_EXISTED=1
[ -e /etc/rc.local ] && RCLOCAL_EXISTED=1
d8_cleanup() {
	rm -f "$D8_CRON" "$D8_UNIT"
	[ "$D8_HOME_MADE" = 1 ] && rm -rf "$D8_HOME"
}

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
	d8_cleanup
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

d8_home_setup() {
	D8_HOME_MADE=1
	mkdir -p "$D8_HOME/.config/systemd/user"
}

#write-intent cases (a) and (c): a cron file written by redirect and removed then files in the fake home (nothing is enabled or started)
write_ac_cmds() {
	d8_home_setup
	echo "# evt_d8 cron" > "$D8_CRON"
	rm -f "$D8_CRON"
	echo "# evt_d8" > "$D8_HOME/.bashrc"
	echo "# evt_d8" > "$D8_HOME/.profile"
	echo "# evt_d8" > "$D8_HOME/.config/systemd/user/evt_d8.service"
	/bin/cat "$D8_HOME/.bashrc" > /dev/null
}

#write-intent cases (a) to (f); the opens of the existing files in (e) use r+ which cannot create or truncate a file and /etc/ld.so.preload and /etc/rc.local are only touched if they do not exist
write_cmds() {
	write_ac_cmds
	printf '[Unit]\nDescription=evt_d8 test unit\n' > "$D8_UNIT"
	rm -f "$D8_UNIT"
	/bin/cat /etc/ld.so.preload > /dev/null 2>&1 || true
	/bin/cat /etc/profile > /dev/null
	/bin/cat /etc/pam.d/sudo > /dev/null 2>&1 || true
	/bin/ls /etc/cron.d > /dev/null
	[ -e /etc/ld.so.preload ] || python3 -c "open('/etc/ld.so.preload','r+')" EVT_D8_PRELOAD 2> /dev/null || true
	[ -e /etc/rc.local ] || python3 -c "open('/etc/rc.local','r+')" EVT_D8_RCLOCAL 2> /dev/null || true
	python3 -c "open('/etc/profile','r+').close()" EVT_D8_PROFILE
	echo "# evt_d8 append" >> "$D8_HOME/.bash_logout"
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
write_cmds
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
write_ac_cmds
stop_loader
start_loader "$OUT/events_fileentry.jsonl" "$OUT/loader_fileentry.stderr" --file-at-entry || exit 1
file_cmds
load_cmds
write_ac_cmds
stop_loader

#validate
BCC_ARGS=()
[ -s "$OUT/execsnoop.txt" ] && BCC_ARGS+=(--execsnoop "$OUT/execsnoop.txt")
[ -s "$OUT/exitsnoop.txt" ] && BCC_ARGS+=(--exitsnoop "$OUT/exitsnoop.txt")
python3 tests/validate.py "$OUT/events.jsonl" --threads-all "$OUT/events_threads.jsonl" \
	"${BCC_ARGS[@]}" --max-args "$MAX_ARGS" --arg-cap "$ARG_CAP" --burst "$BURST" \
	--sudo-uid "${SUDO_UID:-0}" --sudo-gid "${SUDO_GID:-0}" \
	--net4-port "${NET4_PORT:-0}" --net6-port "${NET6_PORT:-0}" \
	--file-exit "$OUT/events_fileexit.jsonl" --file-entry "$OUT/events_fileentry.jsonl" \
	--exit-stats "$OUT/loader_fileexit.stderr" --entry-stats "$OUT/loader_fileentry.stderr" \
	--preload-existed "$PRELOAD_EXISTED" --rclocal-existed "$RCLOCAL_EXISTED" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}
grep -H file_stats "$OUT"/loader*.stderr | tee -a "$OUT/report.txt"

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in telemetry/$OUT"
exit "$STATUS"
