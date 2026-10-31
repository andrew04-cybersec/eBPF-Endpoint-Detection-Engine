set -eu
mkdir -p "$EVT_EVAL_WORK"
chmod 755 "$EVT_EVAL_WORK"
ln -s /usr/bin/python3 "$EVT_EVAL_WORK/sudo"
cat > "$EVT_EVAL_WORK/priv_sim.py" <<'PY'
import os
import sys

print(sys.argv[1])
os.setresgid(61234, 61234, 0)
os.setresuid(61234, 61234, 0)
pid = os.fork()
if pid == 0:
    os.setresuid(0, 0, 0)
    os.execv("/bin/true", ["true"])
os.waitpid(pid, 0)
PY
chmod 644 "$EVT_EVAL_WORK/priv_sim.py"
