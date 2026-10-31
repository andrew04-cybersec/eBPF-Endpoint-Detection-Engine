read -r PORT < "$EVT_EVAL_WORK/port"
curl -s -o "$EVT_EVAL_WORK/$1.sh" "http://127.0.0.1:$PORT/payload.sh"
chmod +x "$EVT_EVAL_WORK/$1.sh"
"$EVT_EVAL_WORK/$1.sh"
:
