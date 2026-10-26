#!/bin/bash
#run loader | normalizer | runner; start a service-named parent that forks a child shell plus two controls and stops the pipe and then validate the saved alerts
#WSL usage:  sudo bash detections/tests/live_test.sh (telemetry loader must be built first)
#output is saved under detections/tests/out/<timestamp>/ and is kept as evidence
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

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
#copies live outside the repo and their names are what the process name; comm, becomes after exec
TMP=$(mktemp -d /tmp/evt_d1.XXXXXX)
cp /bin/bash "$TMP/nginx"
cp /bin/bash "$TMP/evt_notaservice"
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "service_copy: $TMP/nginx"
	echo "control_copy: $TMP/evt_notaservice"
} > "$OUT/env.txt"

cleanup() {
	[ -s "$OUT/loader.pid" ] && kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

#the first subshell records its own pid and then becomes the loader so it can be stopped by pid
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

#each bash runs a command list starting with a fork and not an exec in place; the child is a shell
"$TMP/nginx" -c '/bin/sh -c "/bin/echo EVT_D1_SERVICE" ; true' 2> /dev/null
"$TMP/evt_notaservice" -c '/bin/sh -c "/bin/echo EVT_D1_CONTROL" ; true' 2> /dev/null
/bin/sh -c '/bin/echo EVT_D1_PLAIN ; true' 2> /dev/null

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"

python3 "$HERE/validate_live.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--service-exe "$TMP/nginx" --control-exe "$TMP/evt_notaservice" \
	--runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
