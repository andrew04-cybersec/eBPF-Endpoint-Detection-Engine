mkdir -p "$EVT_EVAL_HOME/.ssh"
ssh-keygen -q -t ed25519 -N "" -f "$EVT_EVAL_HOME/.ssh/id_ed25519"
:
