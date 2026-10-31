set -eu
mkdir -p "$EVT_EVAL_WORK"
cat > "$EVT_EVAL_WORK/passwd" <<PASSWD
demo_user:x:1001:1001:Demo User:$EVT_EVAL_HOME:/bin/bash
PASSWD
cat > "$EVT_EVAL_WORK/shadow" <<'SHADOW'
demo_user:$6$synthetic$not_a_real_password_hash:20000:0:99999:7:::
SHADOW
