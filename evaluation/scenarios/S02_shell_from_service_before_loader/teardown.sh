if [ -f "$EVT_EVAL_WORK/helper.pid" ]; then
	pid=$(cat "$EVT_EVAL_WORK/helper.pid")
	timeout 5 sh -c "echo quit > '$EVT_EVAL_WORK/cmd.fifo'" 2> /dev/null || true
	sleep 0.5
	kill "$pid" 2> /dev/null || true
fi
rm -rf "$EVT_EVAL_WORK"
