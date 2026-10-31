set -eu
mkdir -p "$EVT_EVAL_TMP"
printf 'import sys\nprint("evt_eval staged", sys.argv[1])\n' > "$EVT_EVAL_TMP/x.py"
