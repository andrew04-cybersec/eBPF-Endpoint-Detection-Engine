#!/bin/bash
#run loader | normalizer | runner; start chains of shells and interpreters from separate bash -c processes (nested inline code, controls and chains broken by a program that is not watched) and then validate the saved alerts
#WSL usage: sudo bash detections/tests/live_test_interp.sh (telemetry loader must be built first)
#output is saved under detections/tests/out/<timestamp>-interp_chain/ and is kept as evidence
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

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-interp_chain
mkdir -p "$OUT"
BASE=$(mktemp -d /opt/evt_interp.XXXXXX)
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

#the command strings are built with shlex so the nesting of quotes is exact where each ends in "; :" because bash and sh run a lone last command in place of themselves which would remove them from the chain
python3 - "$BASE" "$OUT/cases.json" <<'PY'
import json
import shlex
import sys

base = sys.argv[1]


def py(code):
    return "python3 -c " + shlex.quote(code)


def put(name, text):
    with open("%s/%s" % (base, name), "w") as f:
        f.write(text)


a3 = py('print("EVT_INTERP_A")') + " ; :"
a2 = "import os; os.system(%r)" % a3
put("a.cmd", py(a2) + " ; :")
put("b.cmd", py('print("EVT_INTERP_B")') + " ; :")
c3 = "echo EVT_INTERP_C ; :"
c2 = "bash -c " + shlex.quote(c3) + " ; :"
put("c.cmd", "bash -c " + shlex.quote(c2) + " ; :")
put("e1.cmd", py('import subprocess; subprocess.run(["/bin/true", "EVT_INTERP_E1"])') + " ; :")
#the loader keeps 127 bytes of each argument so nested e2 code is read from a file to keep the marker inside the bash -c argument
put("e2.py", '''import subprocess, sys
m = sys.argv[1]
subprocess.run(["xargs", "-r", "sh", "-c", "python3 -c 'print(\\"%s\\")' ; :" % m], input=b"x\\n")
''')
put("e2.cmd", py('exec(open("%s/e2.py").read())' % base) + " EVT_INTERP_E2 ; :")
put("d1.sh", 'python3 %s/d2.py "$1"\n:\n' % base)
put("d2.py", 'import subprocess, sys\nsubprocess.run(["sh", "%s/d3.sh", sys.argv[1]])\n' % base)
put("d3.sh", 'python3 %s/d4.py "$1"\n:\n' % base)
put("d4.py", "import sys\nprint(sys.argv[1])\n")
json.dump({"base": base}, open(sys.argv[2], "w"))
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "work_dir: $BASE"
	echo "bash: $(bash --version | head -1)"
	echo "sh: $(readlink -f /bin/sh)"
	echo "python: $(python3 --version 2>&1)"
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
{
	bash -c "$(cat "$BASE/a.cmd")"
	bash -c "$(cat "$BASE/b.cmd")"
	bash -c "$(cat "$BASE/c.cmd")"
	bash "$BASE/d1.sh" EVT_INTERP_D
	bash -c "$(cat "$BASE/e1.cmd")"
	bash -c "$(cat "$BASE/e2.cmd")"
} > "$OUT/cases.out" 2>&1

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"

remove_files
python3 "$HERE/validate_live_interp.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
