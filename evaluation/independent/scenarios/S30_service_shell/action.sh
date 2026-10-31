set -eu
marker="$1"

bash -c '
  sleep 1
  bash -c '\''printf "%s\n" "$1" > "$2"'\'' worker "$1" "$2"
' service_worker "$marker" "$EVT_EVAL_WORK/command_result"

cat "$EVT_EVAL_WORK/command_result"
