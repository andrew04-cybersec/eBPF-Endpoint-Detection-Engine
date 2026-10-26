#!/bin/bash
#run loader | normalizer | runner; make outbound connects to local listener from sus and ordinary processes then validate the saved alerts
#WSL usage: sudo bash detections/tests/live_test_outbound.sh (telemetry loader must be built first; SKIP_SLOW=1 skips the case that waits past the window)
#output is saved under detections/tests/out/<timestamp>-outbound_after_exec/ and is kept as evidence
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
DET=$(dirname "$HERE")
ROOT=$(dirname "$DET")
LOADER=$ROOT/telemetry/build/exec_exit_loader
NORMALIZER=$ROOT/normalizer/normalize.py
RUNNER=$DET/runner.py

if [ "$(id -u)" -ne 0 ]; then
	echo "run this with sudo" >&2
	exit 2
fi
if [ ! -x "$LOADER" ]; then
	echo "build the loader first: make -C telemetry" >&2
	exit 2
fi
CURL=$(command -v curl)
if [ -z "$CURL" ]; then
	echo "curl is missing. Install it in WSL with: sudo apt update && sudo apt install -y curl" >&2
	exit 2
fi
if ! command -v python3 > /dev/null; then
	echo "python3 is missing. Install it in WSL with: sudo apt update && sudo apt install -y python3" >&2
	exit 2
fi

#first non-loopback IPv4 address; without one no case can run so every case is reported as skipped and the script ends cleanly
ADDR=$(ip -4 -o addr show scope global 2> /dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
if [ -z "$ADDR" ]; then
	for c in a b c d e f g; do echo "SKIP  case $c: no non-loopback IPv4 address on this machine"; done
	echo ""
	echo "0 checks, 0 failed (7 cases skipped)"
	exit 0
fi

WINDOW_NS=$(python3 -c "import sys; sys.path.insert(0, '$DET'); import outbound_after_exec as o; print(o.CONNECT_WINDOW_NS)")
SLEEP_S=$((WINDOW_NS / 1000000000 + 5))
SLOW=True
[ "${SKIP_SLOW:-0}" = 1 ] && SLOW=False

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-outbound_after_exec
mkdir -p "$OUT"
#/opt is not under /tmp so exec_from_tmp will be staying quiet so the copy of curl goes to /dev/shm on purpose because that is a sus directory
BASE=$(mktemp -d /opt/evt_d7.XXXXXX)
SHM=$(mktemp -d /dev/shm/evt_d7.XXXXXX)
cp "$CURL" "$SHM/evt_d7_fetch"

LISTENER_PID=""
SLOW_PID=""
cleanup() {
	[ -n "$SLOW_PID" ] && kill "$SLOW_PID" 2>/dev/null
	[ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null
	[ -s "$OUT/loader.pid" ] && kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
	rm -rf "$BASE" "$SHM"
}
trap cleanup EXIT

#one listener process serves the non-loopback address and on the same port: 127.0.0.1 so case b is a real connection to a loopback listener
cat > "$BASE/listener.py" <<'PY'
import socket, sys, threading
addr, portfile = sys.argv[1], sys.argv[2]
a = socket.socket()
a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
a.bind((addr, 0))
a.listen(16)
port = a.getsockname()[1]
b = socket.socket()
b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
b.bind(("127.0.0.1", port))
b.listen(16)
open(portfile + ".tmp", "w").write(str(port))
import os
os.rename(portfile + ".tmp", portfile)
def serve(s):
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(1)
            c.recv(1024)
        except OSError:
            pass
        try:
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        c.close()
threading.Thread(target=serve, args=(b,), daemon=True).start()
serve(a)
PY
python3 "$BASE/listener.py" "$ADDR" "$BASE/port" > "$OUT/listener.log" 2>&1 &
LISTENER_PID=$!
for _ in $(seq 1 50); do
	[ -s "$BASE/port" ] && break
	sleep 0.1
done
if [ ! -s "$BASE/port" ]; then
	echo "listener did not start:" >&2
	cat "$OUT/listener.log" >&2
	exit 1
fi
PORT=$(cat "$BASE/port")

python3 - "$OUT/cases.json" <<PY
import json, sys
json.dump({"addr": "$ADDR", "port": $PORT, "window_ns": $WINDOW_NS, "slow": $SLOW, "shm_exe": "$SHM/evt_d7_fetch",
           "curl": "$CURL"}, open(sys.argv[1], "w"), indent=1)
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "address: $ADDR"
	echo "port: $PORT"
	echo "window_ns: $WINDOW_NS"
	echo "slow_case: $SLOW"
} > "$OUT/env.txt"

( echo $BASHPID > "$OUT/loader.pid"; exec "$LOADER" 2> "$OUT/loader.stderr" ) \
	| tee "$OUT/events.jsonl" \
	| python3 "$NORMALIZER" 2> "$OUT/normalizer.stderr" \
	| tee "$OUT/normalized.jsonl" \
	| python3 "$RUNNER" -o "$OUT/alerts.jsonl" 2> "$OUT/runner.stderr" &
PIPE=$!

ATTACHED=0
for _ in $(seq 1 100); do
	grep -q "attached" "$OUT/loader.stderr" 2>/dev/null && ATTACHED=1 && break
	sleep 0.1
done
if [ "$ATTACHED" -ne 1 ]; then
	echo "loader did not attach:" >&2
	cat "$OUT/loader.stderr" >&2
	exit 1
fi

CODE_A="x='EVT_D7_A';import socket;socket.create_connection(('$ADDR',$PORT)).close()"
CODE_B="x='EVT_D7_B';import socket;socket.create_connection(('127.0.0.1',$PORT)).close()"
CODE_F="x='EVT_D7_F';import socket;[socket.create_connection(('$ADDR',$PORT)).close() for _ in range(5)]"
CODE_G="x='EVT_D7_G';import socket,time;time.sleep($SLEEP_S);socket.create_connection(('$ADDR',$PORT)).close()"
if [ "$SLOW" = True ]; then
	python3 -c "$CODE_G" &
	SLOW_PID=$!
fi
python3 -c "$CODE_A"
python3 -c "$CODE_B"
bash -c ": EVT_D7_C ; exec 3<>/dev/tcp/$ADDR/$PORT ; true"
"$SHM/evt_d7_fetch" -s -o /dev/null "http://$ADDR:$PORT/EVT_D7_D"
#case e is a control since normal curl is not sus by its name because curl is a common and legitimate client
"$CURL" -s -o /dev/null "http://$ADDR:$PORT/EVT_D7_E"
python3 -c "$CODE_F"
if [ -n "$SLOW_PID" ]; then
	wait "$SLOW_PID"
	SLOW_PID=""
fi

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"
echo "IPv6 is not exercised live; the unit tests cover it" >> "$OUT/env.txt"

python3 "$HERE/validate_live_outbound.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
