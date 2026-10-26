#!/bin/bash
#run loader | normalizer | runner; read sensitive files with copies of cat (alone, renamed sudo, below a copy of bash named nginx and one with unlisted name) and validate the saved alerts
#WSL usage: sudo bash detections/tests/live_test_files.sh (telemetry loader must be built first)
#output is saved under detections/tests/out/<timestamp>-sensitive_file_access/ and is kept as evidence
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
DET=$(dirname "$HERE")
ROOT=$(dirname "$DET")
LOADER=$ROOT/telemetry/build/exec_exit_loader
NORMALIZER=$ROOT/normalizer/normalize.py
RUNNER=$DET/runner.py
FAKE_HOME=/home/evt_d5user

if [ "$(id -u)" -ne 0 ]; then
	echo "run this with sudo" >&2
	exit 2
fi
if [ ! -x "$LOADER" ]; then
	echo "build the loader first: make -C telemetry" >&2
	exit 2
fi
if [ -e "$FAKE_HOME" ]; then
	echo "$FAKE_HOME already exists, so it is not touched; remove it by hand and run again" >&2
	exit 2
fi

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-sensitive_file_access
mkdir -p "$OUT"
BASE=$(mktemp -d /opt/evt_d5.XXXXXX)
MADE_HOME=0
cleanup() {
	[ -s "$OUT/loader.pid" ] && kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
	rm -rf "$BASE"
	[ "$MADE_HOME" = 1 ] && rm -rf "$FAKE_HOME"
}
trap cleanup EXIT

mkdir -p "$FAKE_HOME/.ssh"
MADE_HOME=1
: > "$FAKE_HOME/.ssh/id_ed25519"
: > "$FAKE_HOME/.ssh/id_ed25519.pub"
: > "$FAKE_HOME/.ssh/known_hosts"
cp /bin/cat "$BASE/cat"
#the copy named sudo shows what the weakness is on purpose: the rule first reads the process name so for a renamed cat, it is treated as the real sudo and its open of /etc/shadow is then suppressed
cp /bin/cat "$BASE/sudo"
cp /bin/bash "$BASE/nginx"
cp /bin/bash "$BASE/evt_notaservice"
python3 - "$OUT/cases.json" <<PY
import json, sys
json.dump({"base": "$BASE", "home": "$FAKE_HOME"}, open(sys.argv[1], "w"), indent=1)
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "work_dir: $BASE"
	echo "fake_home: $FAKE_HOME"
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

SSH=$FAKE_HOME/.ssh
"$BASE/cat" /etc/shadow > /dev/null
"$BASE/sudo" /etc/shadow > /dev/null
"$BASE/cat" "$SSH/id_ed25519" > /dev/null
"$BASE/cat" "$SSH/id_ed25519.pub" "$SSH/known_hosts" > /dev/null
"$BASE/cat" /etc/passwd > /dev/null
#each command list ends in true so bash 'forks the cat' and doesnt replace itself with it
"$BASE/nginx" -c "$BASE/cat /etc/passwd > /dev/null ; true"
"$BASE/evt_notaservice" -c "$BASE/cat /etc/passwd > /dev/null ; true"
"$BASE/cat" /home/evt_nouser/.ssh/id_rsa > /dev/null 2>&1 || true

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"

python3 "$HERE/validate_live_files.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
