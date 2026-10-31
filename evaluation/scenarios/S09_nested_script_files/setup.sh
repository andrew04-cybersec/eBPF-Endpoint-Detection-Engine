set -eu
mkdir -p "$EVT_EVAL_WORK"
printf 'python3 "${0%%/*}/d2.py" "$1"\n:\n' > "$EVT_EVAL_WORK/d1.sh"
printf 'import os, subprocess, sys\nsubprocess.run(["sh", os.path.join(os.path.dirname(os.path.abspath(__file__)), "d3.sh"), sys.argv[1]])\n' > "$EVT_EVAL_WORK/d2.py"
printf 'python3 "${0%%/*}/d4.py" "$1"\n:\n' > "$EVT_EVAL_WORK/d3.sh"
printf 'import sys\nprint(sys.argv[1])\n' > "$EVT_EVAL_WORK/d4.py"
