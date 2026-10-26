#!/bin/bash
#run loader | normalizer | runner; serve as a harmless script from a local web server running download then chmod and then exec chains and their controls, then validate the saved alerts
#WSL usage: sudo bash detections/tests/live_test_chain.sh (telemetry loader must be built first and also curl must be installed)
#output is saved under detections/tests/out/<timestamp>-download_chmod_exec/ and is kept as evidence
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
if ! command -v curl > /dev/null; then
	echo "curl is missing. Install it in WSL with: sudo apt update && sudo apt install -y curl" >&2
	exit 2
fi
HAVE_WGET=False
command -v wget > /dev/null && HAVE_WGET=True

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-download_chmod_exec
mkdir -p "$OUT"
#/opt is on the WSL root filesystem so files there can be executed; not under /tmp, /var/tmp or /dev/shm so exec_from_tmp will stay quiet
BASE=$(mktemp -d /opt/evt_d3.XXXXXX)
WWW=$BASE/www
DA=$BASE/a_curl
DB=$BASE/b_wget
DC=$BASE/c_relative
DD=$BASE/d_controls
mkdir -p "$WWW" "$DA" "$DB" "$DC" "$DD"
for n in a b c d1 d3; do
	printf '#!/bin/sh\necho EVT_D3_PAYLOAD_%s\n' "$n" > "$WWW/payload_$n.sh"
done
printf '#!/bin/sh\necho EVT_D3_PAYLOAD_d2\n' > "$DD/local_d2"

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
URL=http://127.0.0.1:$PORT

SERVER_PID=""
cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
	[ -s "$OUT/loader.pid" ] && kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
	rm -rf "$BASE"
}
trap cleanup EXIT

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WWW" > "$OUT/server.log" 2>&1 &
SERVER_PID=$!
READY=0
for _ in $(seq 1 50); do
	python3 -c 'import sys,urllib.request;urllib.request.urlopen(sys.argv[1]).read()' "$URL/payload_a.sh" 2> /dev/null && READY=1 && break
	sleep 0.1
done
if [ "$READY" -ne 1 ]; then
	echo "web server did not start:" >&2
	cat "$OUT/server.log" >&2
	exit 1
fi

python3 - "$OUT/cases.json" <<PY
import json, sys
cases = {
    "wget": $HAVE_WGET,
    "a": {"download": "$DA/app_a", "final": "$DA/app_a"},
    "b": {"download": "$DB/app_b", "final": "$DB/app_b"},
    "c": {"name": "payload_c.sh", "final": "./payload_c.sh", "dir": "$DC"},
    "d1": {"path": "$DD/app_d1"},
    "d2": {"path": "$DD/local_d2"},
    "d3": {"path": "$DD/app_d3"},
}
json.dump(cases, open(sys.argv[1], "w"), indent=1)
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "work_dir: $BASE"
	echo "server: $URL"
	echo "wget_installed: $HAVE_WGET"
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

curl -sS -o "$DA/app_a" "$URL/payload_a.sh"
chmod +x "$DA/app_a"
"$DA/app_a" > /dev/null
if [ "$HAVE_WGET" = True ]; then
	wget -q -O "$DB/app_b" "$URL/payload_b.sh"
	chmod +x "$DB/app_b"
	"$DB/app_b" > /dev/null
fi
#case c: fresh bash runs all three steps by relative name and the trailing true keeps the last step from replacing the shell
bash -c 'cd "$1" && curl -sS -O "$2" ; chmod +x payload_c.sh ; ./payload_c.sh > /dev/null ; true' _ "$DC" "$URL/payload_c.sh"
curl -sS -o "$DD/app_d1" "$URL/payload_d1.sh"
"$DD/app_d1" > /dev/null 2>&1 || true
chmod +x "$DD/local_d2"
"$DD/local_d2" > /dev/null
curl -sS -o "$DD/app_d3" "$URL/payload_d3.sh"
chmod +x "$DD/app_d3"

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
SERVER_PID=""
echo "pipeline finished" >> "$OUT/env.txt"

python3 "$HERE/validate_live_chain.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
