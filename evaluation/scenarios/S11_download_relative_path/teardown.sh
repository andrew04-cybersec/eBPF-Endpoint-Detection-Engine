if [ -f "$EVT_EVAL_WORK/server.pid" ]; then
	kill "$(cat "$EVT_EVAL_WORK/server.pid")" 2> /dev/null || true
fi
rm -rf "$EVT_EVAL_WORK"
