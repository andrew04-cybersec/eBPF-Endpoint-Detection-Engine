read -r ADDR < "$EVT_EVAL_WORK/addr"
read -r PORT < "$EVT_EVAL_WORK/port"
bash -c 'exec 3<>/dev/tcp/$1/$2; : $3' evt_eval_connect "$ADDR" "$PORT" "$1"
:
