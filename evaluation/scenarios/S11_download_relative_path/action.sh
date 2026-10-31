read -r PORT < "$EVT_EVAL_WORK/port"
cd "$EVT_EVAL_WORK"
curl -sO "http://127.0.0.1:$PORT/$1.sh"
chmod +x "$1.sh"
"./$1.sh"
:
