#!/bin/bash
#run loader | normalizer | runner; change uids from separate python3 processes (a granted request, a denied request, a python3 named sudo and controls) and then validate the saved alerts
#WSL usage: sudo bash detections/tests/live_test_priv.sh (telemetry loader must be built first)
#output is saved under detections/tests/out/<timestamp>-privilege/ and is kept as evidence
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
DET=$(dirname "$HERE")
ROOT=$(dirname "$DET")
LOADER=$ROOT/telemetry/build/exec_exit_loader
NORMALIZER=$ROOT/normalizer/normalize.py
RUNNER=$DET/runner.py
UNPRIV=61234

if [ "$(id -u)" -ne 0 ]; then
	echo "run this with sudo" >&2
	exit 2
fi
if [ ! -x "$LOADER" ]; then
	echo "build the loader first: make -C telemetry" >&2
	exit 2
fi

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-privilege
mkdir -p "$OUT"
BASE=$(mktemp -d /opt/evt_priv.XXXXXX)
chmod 755 "$BASE"
remove_files() {
	cd "$HERE"
	rm -rf "$BASE"
}
cleanup() {
	[ -s "$OUT/loader.pid" ] && kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
	remove_files
}
trap cleanup EXIT

cat > "$BASE/priv_sim.py" <<'PY'
import os
import sys

print(sys.argv[1])
os.setresuid(61234, 61234, 0)
pid = os.fork()
if pid == 0:
    os.setresuid(0, 0, 0)
    os.execv("/bin/true", ["true"])
os.waitpid(pid, 0)
PY
chmod 644 "$BASE/priv_sim.py"

#symlink to python3 is tried first and gives comm sudo only if kernel names the process after link; a copy is used if it doesnt
SUDO_KIND=symlink
ln -s /usr/bin/python3 "$BASE/sudo"
if [ "$("$BASE/sudo" -c "print(open('/proc/self/comm').read().strip())" 2> /dev/null)" != "sudo" ]; then
	rm -f "$BASE/sudo"
	cp "$(readlink -f /usr/bin/python3)" "$BASE/sudo"
	SUDO_KIND=copy
fi
python3 - "$OUT/cases.json" <<PY
import json, sys
json.dump({"base": "$BASE", "uid": $UNPRIV, "sudo_kind": "$SUDO_KIND"}, open(sys.argv[1], "w"), indent=1)
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "work_dir: $BASE"
	echo "unprivileged uid and gid: $UNPRIV (no such account is created)"
	echo "sudo-named binary: $SUDO_KIND"
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

cd "$BASE"
python3 "$BASE/priv_sim.py" EVT_PRIV_A
#request is denied (uid 61234 has no saved or effective uid 0) so the process never becomes root and the detection still alerts because the hook only sees the request
setpriv --reuid=$UNPRIV --regid=$UNPRIV --clear-groups python3 -c "
import os, sys
print(sys.argv[1])
try:
    os.setuid(0)
except PermissionError:
    print('denied')
" EVT_PRIV_B
#same script as case a under the name sudo which is the name is on the expected list so this shows that a renamed binary is suppressed
"$BASE/sudo" "$BASE/priv_sim.py" EVT_PRIV_C
setpriv --reuid=$UNPRIV --regid=$UNPRIV --clear-groups python3 -c "import os; os.setuid($UNPRIV)" EVT_PRIV_D1
setpriv --reuid=$UNPRIV --regid=$UNPRIV --clear-groups python3 -c "import os; os.setreuid(-1, $UNPRIV)" EVT_PRIV_D2
python3 -c "import os; os.setuid(0)" EVT_PRIV_D3

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"

remove_files
python3 "$HERE/validate_live_priv.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
