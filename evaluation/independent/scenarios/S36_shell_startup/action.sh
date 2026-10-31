set -eu
cat > "$EVT_EVAL_HOME/.bashrc" <<'RC'
printf '%s\n' "$EVT_EVAL_MARKER" > "$EVT_EVAL_WORK/shell_startup_result"
RC
bash --noprofile --rcfile "$EVT_EVAL_HOME/.bashrc" -ic 'exit 0'
