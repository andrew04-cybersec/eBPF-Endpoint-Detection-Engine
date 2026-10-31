SLEEP_SECONDS=70
read -r ADDR < "$EVT_EVAL_WORK/addr"
read -r PORT < "$EVT_EVAL_WORK/port"
bash -c 'sleep $4; exec 3<>/dev/tcp/$1/$2; : $3' evt_eval_connect "$ADDR" "$PORT" "$1" "$SLEEP_SECONDS"
:
