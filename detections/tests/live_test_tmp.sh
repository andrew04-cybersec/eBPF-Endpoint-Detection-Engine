#!/bin/bash
#run loader | normalizer | runner; executes copies of a harmless binary from /tmp, /var/tmp, /dev/shm and control directory and then validates the saved alerts
#WSL usage: sudo bash detections/tests/live_test_tmp.sh (telemetry loader must be built first)
#output is saved under detections/tests/out/<timestamp>-exec_from_tmp/ and is kept as evidence
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

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-exec_from_tmp
mkdir -p "$OUT"
#/opt is on the WSL root filesystem so normally it is writable by root only but not under any sus directory and/or not a drvfs mount
D_TMP=$(mktemp -d /tmp/evt_d2.XXXXXX)
D_VAR=$(mktemp -d /var/tmp/evt_d2.XXXXXX)
D_SHM=$(mktemp -d /dev/shm/evt_d2.XXXXXX)
D_CTL=$(mktemp -d /opt/evt_d2.XXXXXX)
DIRS=("$D_TMP" "$D_VAR" "$D_SHM" "$D_CTL")
for d in "${DIRS[@]}"; do
	[ -d "$d" ] || { echo "could not create a test directory" >&2; rm -rf "${DIRS[@]}"; exit 2; }
done
cp /bin/true "$D_TMP/evt_d2_true_tmp"
cp /bin/true "$D_VAR/evt_d2_true_vartmp"
cp /bin/true "$D_SHM/evt_d2_true_shm"
cp /bin/true "$D_CTL/evt_d2_true_ctl"
cp /bin/true "$D_TMP/evt_d2_true_rel"
FAILED_PATH=$D_TMP/evt_d2_does_not_exist

python3 - "$OUT/cases.json" <<PY
import json, sys
cases = {
    "suspect": [
        {"label": "/tmp", "path": "$D_TMP/evt_d2_true_tmp", "marker": "EVT_D2_TMP"},
        {"label": "/var/tmp", "path": "$D_VAR/evt_d2_true_vartmp", "marker": "EVT_D2_VARTMP"},
        {"label": "/dev/shm", "path": "$D_SHM/evt_d2_true_shm", "marker": "EVT_D2_SHM"},
    ],
    "control": {"dir": "$D_CTL", "path": "$D_CTL/evt_d2_true_ctl", "marker": "EVT_D2_CTL"},
    "relative": {"marker": "EVT_D2_REL"},
    "failed": {"path": "$FAILED_PATH", "marker": "EVT_D2_FAIL"},
}
json.dump(cases, open(sys.argv[1], "w"), indent=1)
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	for d in "${DIRS[@]}"; do echo "test_dir: $d"; done
} > "$OUT/env.txt"

cleanup() {
	[ -s "$OUT/loader.pid" ] && kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
	rm -rf "${DIRS[@]}"
}
trap cleanup EXIT

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

"$D_TMP/evt_d2_true_tmp" EVT_D2_TMP 2> /dev/null
"$D_VAR/evt_d2_true_vartmp" EVT_D2_VARTMP 2> /dev/null
"$D_SHM/evt_d2_true_shm" EVT_D2_SHM 2> /dev/null
"$D_CTL/evt_d2_true_ctl" EVT_D2_CTL 2> /dev/null
#same kind of copy run by a relative path to record what filename the loader sees
( cd "$D_TMP" && ./evt_d2_true_rel EVT_D2_REL ) 2> /dev/null
"$FAILED_PATH" EVT_D2_FAIL 2> /dev/null || true

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"

python3 "$HERE/validate_live_tmp.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
