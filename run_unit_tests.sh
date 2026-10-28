#!/bin/bash
#runs the unit tests of detections, graph, alerts and normalizer without sudo... each from the directory and with the invocation that works for it; prints one line per suite
#usage: bash run_unit_tests.sh (exit status is 1 if any suite fails)
ROOT=$(cd "$(dirname "$0")" && pwd)
export PYTHONDONTWRITEBYTECODE=1
TOTAL=0
FAILED=0

run_suite() {
	local name=$1 dir=$2 start=$3 out count status
	out=$(cd "$ROOT/$dir" && python3 -m unittest discover -s "$start" -p 'test_*.py' 2>&1)
	count=$(printf '%s\n' "$out" | sed -n 's/^Ran \([0-9]*\) tests\{0,1\} in.*/\1/p' | tail -1)
	count=${count:-0}
	if printf '%s\n' "$out" | grep -q '^OK'; then
		status=OK
	else
		status=FAILED
		FAILED=$((FAILED + 1))
		printf '%s\n' "$out" | tail -20 >&2
	fi
	TOTAL=$((TOTAL + count))
	printf '%-12s %5d tests  %s\n' "$name" "$count" "$status"
}

run_suite detections detections/tests .
run_suite graph graph/tests .
run_suite alerts alerts/tests .
run_suite normalizer normalizer tests

echo "total        $TOTAL tests, $FAILED suite(s) failed"
[ "$FAILED" -eq 0 ]
