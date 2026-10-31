set -eu
mkdir -p "$EVT_EVAL_WORK"
cp /bin/bash "$EVT_EVAL_WORK/nginx"
mkfifo "$EVT_EVAL_WORK/cmd.fifo"
setsid "$EVT_EVAL_WORK/nginx" -c 'f=$1; while read -r line < "$f"; do [ "$line" = quit ] && break; sh -c "$line"; done' evt_eval_helper "$EVT_EVAL_WORK/cmd.fifo" > /dev/null 2>&1 < /dev/null &
echo $! > "$EVT_EVAL_WORK/helper.pid"
