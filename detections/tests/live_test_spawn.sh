#!/bin/bash
#run loader | normalizer | runner; run loops of /bin/true from separate bash -c processes (fast, one below threshold, slow, and two bursts with pause), validate the saved alerts
#WSL usage: sudo bash detections/tests/live_test_spawn.sh (telemetry loader must be built first)
#output is saved under detections/tests/out/<timestamp>-rapid_spawn/ and is kept as evidence
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

THRESHOLD=$(python3 -c "import sys; sys.path.insert(0, '$DET'); import rapid_spawn as r; print(r.SPAWN_THRESHOLD)")
WINDOW_NS=$(python3 -c "import sys; sys.path.insert(0, '$DET'); import rapid_spawn as r; print(r.WINDOW_NS)")
BELOW=$((THRESHOLD - 1))

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-rapid_spawn
mkdir -p "$OUT"
BASE=$(mktemp -d /opt/evt_d6.XXXXXX)
python3 - "$OUT/cases.json" <<PY
import json, sys
json.dump({"threshold": $THRESHOLD, "window_ns": $WINDOW_NS, "below": $BELOW}, open(sys.argv[1], "w"), indent=1)
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "work_dir: $BASE"
	echo "threshold: $THRESHOLD"
	echo "window_ns: $WINDOW_NS"
} > "$OUT/env.txt"

cleanup() {
	[ -s "$OUT/loader.pid" ] && kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
	rm -rf "$BASE"
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

cd "$BASE" || exit 1
#every case is its own bash -c so it has parent node and the marker that comes first in the text so it can survive the argument cap
bash -c ": EVT_D6_A ; for ((i=0;i<60;i++)); do /bin/true EVT_D6_A; done; true"
#b: one child fewer than the threshold; loop counter is arithmetic so no other child (seq for example) is started
bash -c ": EVT_D6_B ; for ((i=0;i<$BELOW;i++)); do /bin/true EVT_D6_B; done; true"
#c: 50 iterations of a child and a sleep; relies on rate and not count because 100 children in all are spread over about ten seconds so no 2 second window holds the threshold
bash -c ": EVT_D6_C ; for ((i=0;i<50;i++)); do /bin/true EVT_D6_C; sleep 0.2; done; true"
#d: loop of case a twice with a pause longer than the window so the burst re-arms
bash -c ": EVT_D6_D ; for ((i=0;i<60;i++)); do /bin/true EVT_D6_D; done; sleep 3.5; for ((i=0;i<60;i++)); do /bin/true EVT_D6_D; done; true"

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"

python3 "$HERE/validate_live_spawn.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
