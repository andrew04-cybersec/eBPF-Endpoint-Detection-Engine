set -eu
mkdir -p "$EVT_EVAL_WORK"
echo "$EVT_EVAL_NONLOOPBACK_IPV4" > "$EVT_EVAL_WORK/addr"
python3 -c 'import socket,sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 0))
s.listen(8)
open(sys.argv[2], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    c.close()' "$EVT_EVAL_NONLOOPBACK_IPV4" "$EVT_EVAL_WORK/port" > "$EVT_EVAL_WORK/listener.log" 2>&1 < /dev/null &
echo $! > "$EVT_EVAL_WORK/listener.pid"
up=0
for _ in $(seq 1 50); do
	if [ -s "$EVT_EVAL_WORK/port" ]; then
		up=1
		break
	fi
	sleep 0.2
done
if [ "$up" != 1 ]; then
	echo "the listener did not come up" >&2
	exit 1
fi
