set -eu
mkdir -p "$EVT_EVAL_WORK"
printf '# evt_eval staged\n' > "$EVT_EVAL_WORK/$EVT_EVAL_MARKER.cron"
stat -c 'device %d %n' "$EVT_EVAL_WORK" "$EVT_EVAL_CRON_DIR"
