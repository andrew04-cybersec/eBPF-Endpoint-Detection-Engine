#!/bin/bash
#run loader | normalizer | runner; write persistence locations from separate bash processes and run renamed copies of true as crontab and systemctl and then validate the saved alerts
#WSL usage: sudo bash detections/tests/live_test_persist.sh (telemetry loader must be built first)
#output is saved under detections/tests/out/<timestamp>-persistence/ and is kept as evidence
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
DET=$(dirname "$HERE")
ROOT=$(dirname "$DET")
LOADER=$ROOT/telemetry/build/exec_exit_loader
NORMALIZER=$ROOT/normalizer/normalize.py
RUNNER=$DET/runner.py
FAKE_HOME=/home/evt_d8user
CRON=/etc/cron.d/evt_d8_cron
UNIT=/etc/systemd/system/evt_d8_unit.service

if [ "$(id -u)" -ne 0 ]; then
	echo "run this with sudo" >&2
	exit 2
fi
if [ ! -x "$LOADER" ]; then
	echo "build the loader first: make -C telemetry" >&2
	exit 2
fi
for p in "$FAKE_HOME" "$CRON" "$UNIT"; do
	if [ -e "$p" ]; then
		echo "$p already exists, so it is not touched; remove it by hand and run again" >&2
		exit 2
	fi
done

OUT=$HERE/out/$(date +%Y%m%d-%H%M%S)-persistence
mkdir -p "$OUT"
BASE=$(mktemp -d /opt/evt_d8p.XXXXXX)
MADE_HOME=0
remove_files() {
	rm -rf "$BASE"
	rm -f "$CRON" "$UNIT"
	[ "$MADE_HOME" = 1 ] && rm -rf "$FAKE_HOME"
}
cleanup() {
	[ -s "$OUT/loader.pid" ] && kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
	remove_files
}
trap cleanup EXIT

MADE_HOME=1
mkdir -p "$FAKE_HOME/.ssh" "$FAKE_HOME/.config/systemd/user"
#dpkg is expected writer by name and the copy of bash named dpkg shows the weakness of that (renamed binary is suppressed)
cp /bin/bash "$BASE/dpkg"
#copies of true under these names exercise the exec trigger logic only and the real crontab and systemctl are never run
cp /bin/true "$BASE/crontab"
cp /bin/true "$BASE/systemctl"
PLAIN=$BASE/plain.txt
PRELOAD_ABSENT=1
[ -e /etc/ld.so.preload ] && PRELOAD_ABSENT=0
python3 - "$OUT/cases.json" <<PY
import json, sys
json.dump({"base": "$BASE", "home": "$FAKE_HOME", "cron": "$CRON", "unit": "$UNIT", "plain": "$PLAIN",
           "preload_absent": $PRELOAD_ABSENT}, open(sys.argv[1], "w"), indent=1)
PY
{
	date -u +"date_utc: %Y-%m-%dT%H:%M:%SZ"
	echo "kernel: $(uname -r)"
	echo "sudo_uid: ${SUDO_UID:-none}"
	echo "work_dir: $BASE"
	echo "fake_home: $FAKE_HOME"
	echo "ld.so.preload absent at start: $PRELOAD_ABSENT"
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

bash -c 'echo "# evt_d8" > /etc/cron.d/evt_d8_cron' EVT_PA
bash -c 'printf "[Unit]\nDescription=evt_d8\n" > /etc/systemd/system/evt_d8_unit.service' EVT_PB
bash -c 'echo "# evt_d8" >> /home/evt_d8user/.bashrc' EVT_PC1
bash -c 'echo "# evt_d8" > /home/evt_d8user/.profile' EVT_PC2
bash -c 'echo "# evt_d8" > /home/evt_d8user/.ssh/authorized_keys' EVT_PC3
bash -c 'echo "# evt_d8" > /home/evt_d8user/.config/systemd/user/evt_d8.service' EVT_PC4
for f in "$CRON" "$UNIT" "$FAKE_HOME/.bashrc" "$FAKE_HOME/.profile" "$FAKE_HOME/.ssh/authorized_keys" \
	"$FAKE_HOME/.config/systemd/user/evt_d8.service"; do
	/bin/cat "$f" > /dev/null
done
rm -f "$CRON" "$UNIT"
"$BASE/dpkg" -c 'echo "# evt_d8" > /etc/cron.d/evt_d8_cron' EVT_PE
rm -f "$CRON"
if [ "$PRELOAD_ABSENT" = 1 ]; then
	python3 -c "open('/etc/ld.so.preload','r+')" EVT_PF 2> /dev/null || true
fi
bash -c 'echo a >> /etc/cron.d/evt_d8_cron; echo b >> /etc/cron.d/evt_d8_cron' EVT_PG
rm -f "$CRON"
"$BASE/crontab" "$BASE/cronfile"
"$BASE/crontab" -
"$BASE/crontab" -l
"$BASE/systemctl" enable evt_d8_unit.service
"$BASE/systemctl" status evt_d8_unit.service
bash -c "echo x > $PLAIN" EVT_PI

sleep 1
kill -INT "$(cat "$OUT/loader.pid")" 2>/dev/null
wait "$PIPE"
echo "pipeline finished" >> "$OUT/env.txt"

remove_files
python3 "$HERE/validate_live_persist.py" --events "$OUT/normalized.jsonl" --alerts "$OUT/alerts.jsonl" \
	--cases "$OUT/cases.json" --runner-stderr "$OUT/runner.stderr" | tee "$OUT/report.txt"
STATUS=${PIPESTATUS[0]}

[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$OUT"
echo "output saved in detections/tests/out/$(basename "$OUT")"
exit "$STATUS"
