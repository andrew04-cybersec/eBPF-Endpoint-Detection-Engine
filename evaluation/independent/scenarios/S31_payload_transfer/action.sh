set -eu
cp "$EVT_EVAL_WORK/remote_payload" "$EVT_EVAL_WORK/received_payload"
chmod 700 "$EVT_EVAL_WORK/received_payload"
"$EVT_EVAL_WORK/received_payload" "$1" "$EVT_EVAL_WORK/execution_result"
