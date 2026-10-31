set -eu
mkdir -p "$EVT_EVAL_HOME"
printf '# evt_eval fake bashrc\nalias ll="ls -l"\nalpha=1\nbeta=2\n' > "$EVT_EVAL_HOME/.bashrc"
