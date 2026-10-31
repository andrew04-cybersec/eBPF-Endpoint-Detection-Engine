set -eu
mkdir -p "$EVT_EVAL_HOME/.ssh"
printf 'not a real key %s\n' "$EVT_EVAL_MARKER" > "$EVT_EVAL_HOME/.ssh/id_ed25519"
chmod 600 "$EVT_EVAL_HOME/.ssh/id_ed25519"
