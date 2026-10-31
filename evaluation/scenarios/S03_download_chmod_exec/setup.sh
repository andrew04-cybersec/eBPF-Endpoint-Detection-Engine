set -eu
mkdir -p "$EVT_EVAL_WORK/serve"
printf '#!/bin/sh\necho evt_eval payload\n' > "$EVT_EVAL_WORK/serve/payload.sh"
echo 18741 > "$EVT_EVAL_WORK/port"
if python3 -c 'import socket,sys; sys.exit(1 if socket.socket().connect_ex(("127.0.0.1", 18741)) == 0 else 0)'; then
	:
else
	echo "port 18741 is already in use" >&2
	exit 1
fi
python3 -m http.server 18741 --bind 127.0.0.1 --directory "$EVT_EVAL_WORK/serve" > "$EVT_EVAL_WORK/server.log" 2>&1 < /dev/null &
echo $! > "$EVT_EVAL_WORK/server.pid"
for _ in $(seq 1 50); do
	python3 -c 'import socket,sys; sys.exit(0 if socket.socket().connect_ex(("127.0.0.1", 18741)) == 0 else 1)' && exit 0
	sleep 0.2
done
echo "the server did not come up" >&2
exit 1
