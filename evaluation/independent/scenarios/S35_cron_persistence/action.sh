set -eu
printf '* * * * * root /bin/bash %s/periodic_task.sh\n' "$EVT_EVAL_WORK" > "$EVT_EVAL_CRON_FILE"
printf '%s\n' "$1" > "$EVT_EVAL_WORK/installation_marker"
