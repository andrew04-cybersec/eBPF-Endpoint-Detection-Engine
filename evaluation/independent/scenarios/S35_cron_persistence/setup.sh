set -eu
mkdir -p "$EVT_EVAL_WORK"
cat > "$EVT_EVAL_WORK/periodic_task.sh" <<'TASK'
#!/bin/bash
printf '%s\n' "$EVT_EVAL_MARKER" > "$EVT_EVAL_WORK/cron_result"
TASK
chmod 700 "$EVT_EVAL_WORK/periodic_task.sh"
