#!/bin/bash
#run loader | normalizer | runner; run python3 below a copy of bash named nginx (direct child and grandchild) and also the same below a copy with an unlisted name and then validate the saved alerts
#WSL usage: sudo bash detections/tests/live_test_ancestry.sh (telemetry loader must be built first, and python3 must be installed)
#output is saved under detections/tests/out/<timestamp>-unusual_ancestry/ and is kept as evidence
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
if ! command -v python3 > /dev/null; then
	echo "python3 is missing. Install it in WSL with: sudo apt update && sudo apt install -y python3" >&2
	exit 2
fi

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-unusual_ancestry
mkdir -p "$OUT"
#/opt is not under /tmp so exec_from_tmp will stay quiet and also its on the WSL root filesystem so the copies can be executed
BASE=$(mktemp -d /opt/evt_d4.XXXXXX)
cp /bin/bash "$BASE/nginx"
cp /bin/bash "$BASE/evt_notaservice"
python3 - "$OUT/cases.json" <<PY
import json, sys
json.dump({"service": "$BASE/nginx", "control": "$BASE/evt_notaservice"}, open(sys.argv[1], "w"), indent=1)
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "work_dir: $BASE"
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

#each command line ends in true so the last command is a fork and not an exec in place; the commands for the grandchild case are passed as an argument to avoid nested quoting
DIRECT='python3 -c "print(\"EVT_D4_DIRECT\")" ; true'
GRAND='python3 -c "print(\"EVT_D4_GRAND\")" ; true'
CTL_DIRECT='python3 -c "print(\"EVT_D4_CTL_DIRECT\")" ; true'
CTL_GRAND='python3 -c "print(\"EVT_D4_CTL_GRAND\")" ; true'
"$BASE/nginx" -c "$DIRECT" > /dev/null
"$BASE/nginx" -c 'sh -c "$1" ; true' _ "$GRAND" > /dev/null
"$BASE/evt_notaservice" -c "$CTL_DIRECT" > /dev/null
"$BASE/evt_notaservice" -c 'sh -c "$1" ; true' _ "$CTL_GRAND" > /dev/null
"$BASE/nginx" -c '/bin/true EVT_D4_TRUE ; true'
python3 -c "print(\"EVT_D4_PLAIN\")" > /dev/null

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"

python3 "$HERE/validate_live_ancestry.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
