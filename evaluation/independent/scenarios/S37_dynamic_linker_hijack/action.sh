set -eu
LD_PRELOAD="$EVT_EVAL_WORK/library.so" /bin/true
cat "$EVT_EVAL_WORK/library_result"
