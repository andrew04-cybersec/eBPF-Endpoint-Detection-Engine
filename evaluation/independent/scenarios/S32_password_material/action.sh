set -eu
cp "$EVT_EVAL_WORK/passwd" "$EVT_EVAL_WORK/collected_passwd"
cp "$EVT_EVAL_WORK/shadow" "$EVT_EVAL_WORK/collected_shadow"
grep '^demo_user:' "$EVT_EVAL_WORK/collected_passwd"
grep '^demo_user:' "$EVT_EVAL_WORK/collected_shadow"
printf '%s\n' "$1" > "$EVT_EVAL_WORK/collection_marker"
