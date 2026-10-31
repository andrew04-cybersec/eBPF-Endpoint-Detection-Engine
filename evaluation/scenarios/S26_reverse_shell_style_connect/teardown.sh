if [ -f "$EVT_EVAL_WORK/listener.pid" ]; then
	kill "$(cat "$EVT_EVAL_WORK/listener.pid")" 2> /dev/null || true
fi
rm -rf "$EVT_EVAL_WORK"
